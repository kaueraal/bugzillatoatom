package main

import "strings"
import "strconv"
import "fmt"
import "errors"
import "net"
import "net/http"
import "net/url"
import "context"
import "time"
import "html"
import "log"
import "flag"
import "regexp"
import "sort"
import "encoding/xml"
import "encoding/hex"
import "crypto/sha256"
import "github.com/kaueraal/bugzillatoatom/throttling"
import "golang.org/x/tools/blog/atom"

const bugzillaDateFormat = "2006-01-02 15:04:05 -0700"
const userAgentName = "bugzillatoatom"

// Networks which are by default blocked
var blockedLocalNetworks []string = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"fec0::/10", // deprecated, but just be sure...
}

// Maximum size a request for a bug-xml is read in byte.
var maxBugRequestRead int64

// Maximum number of requests per second. Set to something negative to disable
var maxRequestsPerSecond int

// throttler to block on during too many requests in a second
var throttler *throttling.Throttler

// Requests the bug from given url
func doRequest(target *url.URL) (string, error) {
	request := http.Request{
		Method: http.MethodGet,
		URL:    target,
		Header: http.Header{
			"User-Agent": {userAgentName + "/" + getVersion()},
		},
	}

	resp, err := http.DefaultClient.Do(&request)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("Request returned status code %d (%s).", resp.StatusCode, http.StatusText(resp.StatusCode)))
	}

	// Read until "<attachment". If this is found close the tags. In any case the string
	// is only read if in the first 1024 bytes the word "bugzilla" appears.
	return readUntilString(resp.Body, "<attachment", "</bug></bugzilla>", "bugzilla", 1024)
}

// Regex for detection of bug numbers in comments. Used in convertXmlToAtom.
// The pre region is used so we don't recognize escaped html as &#1234; as bug number.
var bugNumberRegex *regexp.Regexp = regexp.MustCompile(`(?P<pre>\A|[^&])(?P<all>(?:[Bb]ug |#)(?P<num>\d+))`)

// Regex for detection of attachment uploads in comments. Used in convertXmlToAtom.
var attachmentUploadRegex *regexp.Regexp = regexp.MustCompile(`(?P<pre>\ACreated )(?P<all>attachment (?P<num>\d+))`)

// Somewhat crude regex for detection of most urls in comments. Used in convertXmlToAtom.
var urlRegex *regexp.Regexp = regexp.MustCompile(`\b(?P<all>\w+://\S+)`)

// converts the given xml string into an atom feed
func convertXmlToAtom(inXml string) (string, error) {
	type Who struct {
		Name     string `xml:",chardata"`
		RealName string `xml:"name,attr"`
	}

	getFormatedName := func(w Who) string {
		if w.RealName == "" {
			return w.Name
		} else {
			return w.RealName + " (" + w.Name + ")"
		}
	}

	type Comment struct {
		CommentId    int    `xml:"commentid"`
		CommentCount *int    `xml:"comment_count"`
		AttachmentID int    `xml:"attachid"`
		Who          Who    `xml:"who"`
		When         string `xml:"bug_when"`
		Text         string `xml:"thetext"`
	}

	type InResult struct {
		Urlbase     string    `xml:"urlbase,attr"`
		BugId       int       `xml:"bug>bug_id"`
		Description string    `xml:"bug>short_desc"`
		Comments    []Comment `xml:"bug>long_desc"`
	}

	inResult := InResult{}
	err := xml.Unmarshal([]byte(inXml), &inResult)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error during unmarshalling the xml: %s", err))
	} else if len(inResult.Comments) == 0 {
		// One comment, the initial one, should always be available
		err := errors.New("Zero comments in bug. There should be at least the initial one.")
		return "", err
	}

	updateTime, err := time.Parse(bugzillaDateFormat, inResult.Comments[len(inResult.Comments)-1].When)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Couldn't parse updateTime in initial comment: %s", err))
	}

	inUrl := fmt.Sprintf("%sshow_bug.cgi?id=%d", inResult.Urlbase, inResult.BugId)
	bugUrl := fmt.Sprintf("%sshow_bug.cgi?id=", inResult.Urlbase)
	attachmentUrl := fmt.Sprintf("%sattachment.cgi?id=", inResult.Urlbase)

	feed := &atom.Feed{
		Title:   inResult.Description,
		ID:      inUrl,
		Link:    []atom.Link{atom.Link{Href: inUrl, Rel: "alternate"}},
		Updated: atom.Time(updateTime),
		Author:  &atom.Person{Name: getFormatedName(inResult.Comments[0].Who)},
		Entry:   make([]*atom.Entry, 0, len(inResult.Comments)),
	}

	for i, comment := range inResult.Comments {
		creationTime, err := time.Parse(bugzillaDateFormat, comment.When)
		if err != nil {
			return "", errors.New(fmt.Sprintf("Couldn't parse updateTime in comment %d: %s", i, err))
		}

		// Some xmls do not contain comment_count for whatever reason
		if comment.CommentCount == nil {
			comment.CommentCount = new(int)
			*comment.CommentCount = i
		}

		links := []atom.Link{atom.Link{Href: inUrl + "#c" + strconv.Itoa(*comment.CommentCount), Rel: "alternate"}}
		if comment.AttachmentID != 0 {
			links = append(links, atom.Link{Href: attachmentUrl + strconv.Itoa(comment.AttachmentID), Rel: "enclosure", Title: "Attachment"})
		}

		body := html.EscapeString(comment.Text)
		body = urlRegex.ReplaceAllString(body, `<a href="${all}">${all}</a>`)
		body = attachmentUploadRegex.ReplaceAllString(body, `${pre}<a href="`+attachmentUrl+`${num}">${all}</a>`)
		body = bugNumberRegex.ReplaceAllString(body, `${pre}<a href="`+bugUrl+`${num}">${all}</a>`)
		body = `<pre style="white-space: pre-wrap">` + body + "</pre>"

		// We don't limit the title here too much, because comment.Who can be too
		// large as well. Just to be sure: It needs to be least 3 for the dots.
		maxTitleLength := 100
		title := getFormatedName(comment.Who) + ": " + comment.Text[:min(maxTitleLength, len(comment.Text))]
		if len(title) > maxTitleLength {
			// Find latest space starting three positions before maxTitleLength and cut off
			// If the space is too far away simply cut off without a nice cut.
			// Find lastSpace with maxTitleLength-2, because if this position is a
			// space it is cut out, as title[:lastspace] always cuts at least one char.
			lastSpace := strings.LastIndex(title[:maxTitleLength-2], " ")

			if lastSpace < maxTitleLength*3/4 {
				title = title[:maxTitleLength-3] + "..."
			} else {
				title = title[:lastSpace] + "..."
			}
		}

		entry := &atom.Entry{
			Title:     title,
			ID:        inUrl + "#c" + strconv.Itoa(*comment.CommentCount),
			Link:      links,
			Published: atom.Time(creationTime),
			Updated:   atom.Time(creationTime),
			Author:    &atom.Person{Name: getFormatedName(comment.Who)},
			Content:   &atom.Text{Type: "html", Body: body},
		}

		feed.Entry = append(feed.Entry, entry)
	}

	atom, err := xml.MarshalIndent(feed, "", "\t")
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error during creating the atom feed: %s", err))
	}

	return xml.Header + string(atom), nil
}

// Checks for not allowed targets, defined by the given networks.
// Returns a list of IPs if target is allowed, otherwise
// throws an error
func targetAllowedIPs(target string, forbiddenNetworks []*net.IPNet) ([]net.IP, error) {
	ips, err := net.LookupIP(target)

	if forbiddenNetworks == nil {
		return ips, nil
	}

	if err != nil {
		return []net.IP{}, err
	}

	for _, ip := range ips {
		for _, ipnet := range forbiddenNetworks {
			if ipnet.Contains(ip) {
				log.Printf("Blocked target \"%s\" since it's IP %s is contained in blocked network %s.\n", target, ip, ipnet)
				errStr := fmt.Sprintf("Target \"%s\" blocked.", target)
				return []net.IP{}, errors.New(errStr)
			}
		}
	}

	return ips, nil
}

func handleConvert(w http.ResponseWriter, r *http.Request) {
	// Check for a possible recursive call
	if r.Header != nil {
		for _, agent := range r.Header["User-Agent"] {
			if strings.Contains(agent, userAgentName) {
				log.Printf("Blocked request by %s due to User-Agent \"%s\".\n", r.RemoteAddr, agent)
				errStr := fmt.Sprintf("User-Agent \"%s\" blocked.", r.Header["User-Agent"])
				http.Error(w, errStr, http.StatusForbidden)
				return
			}
		}
	}

	formValueUrl := strings.Trim(r.FormValue("url"), " \t")

	// if the user didn't give a protocol simply assume http
	if !(strings.HasPrefix(formValueUrl, "http://") || strings.HasPrefix(formValueUrl, "https://")) {
		formValueUrl = "http://" + formValueUrl
	}

	target, err := url.Parse(formValueUrl)

	if err != nil {
		log.Printf("Error occurred during parsing the url \"%s\": %s.\n", r.FormValue("url"), err.Error())
		errStr := fmt.Sprintf("Error occurred during parsing the url \"%s\": %s\nAre you sure the url is correct?", r.FormValue("url"), err.Error())
		http.Error(w, errStr, http.StatusBadRequest)
		return
	}

	parsedQuery := target.Query()
	parsedQuery.Set("ctype", "xml")
	target.RawQuery = parsedQuery.Encode()
	target.Fragment = ""

	// Block during too many requests in the last second.
	// Try to handle if a client disconnects while we block.
	if maxRequestsPerSecond >= 0 {
		// The conversion should never fail, unless the go developers break their API
		closeChan := w.(http.CloseNotifier).CloseNotify()

		throttler.RequestTicket()

		select {
		case <-closeChan:
			throttler.ReturnUnusedTicket()
			return
		default:
			throttler.UseTicket()
		}
	}

	inXml, err := doRequest(target)
	if err != nil {
		log.Printf("Error occurred during fetching the url \"%s\": %s\n", target.String(), err.Error())
		errStr := fmt.Sprintf("Error occurred during fetching the url \"%s\": %s\nAre you sure the url is correct?", target.String(), err.Error())
		http.Error(w, errStr, http.StatusInternalServerError)
		return
	}

	atom, err := convertXmlToAtom(inXml)
	if err != nil {
		log.Printf("Error occurred during conversion of the url \"%s\" to atom: %s\n", target.String(), err.Error())
		errStr := fmt.Sprintf("Error occurred during conversion of the url \"%s\" to atom: %s\nAre you sure the url is correct?", target.String(), err.Error())
		http.Error(w, errStr, http.StatusInternalServerError)
		return
	}

	// Generate and check Etag
	etagHash := sha256.Sum256([]byte(atom))
	etag := "\"" + hex.EncodeToString(etagHash[:]) + "\""

	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	header := w.Header()
	header.Set("Etag", etag)
	header.Set("Content-Type", "application/atom+xml; charset=utf-8")
	fmt.Fprintf(w, "%s", atom)
}

func handleMain(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != "/" {
		errStr := fmt.Sprintf("Error %d: Path \"%s\" not found.", http.StatusNotFound, r.URL.Path)
		http.Error(w, errStr, http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "%s", `
<html>
<head>
<title>bugzillatoatom</title>
</head>
<body bgcolor="#FFFFFF">
	<form action=convert>
		Convert a Bugzilla bug entry into an Atom feed. Enter an url:
		<input type="text" name="url">
		<input type="submit" value="convert">
	</form>
	<div style="position: absolute; right: 0px; bottom: 0px; margin: 8px">via <a href="https://github.com/kaueraal/bugzillatoatom">bugzillatoatom</a></div>
</body>
</html>
`)
}

// Parses a given IP or CIDR into a CIDR. IPs are treated as CIDRs with full bitmask
func parseIPOrCIDR(str string) (*net.IPNet, error) {

	if !strings.Contains(str, "/") {
		if strings.Contains(str, ":") {
			str = str + "/128"
		} else {
			str = str + "/32"
		}
	}

	_, ipnet, err := net.ParseCIDR(str)
	return ipnet, err
}

// To allow forbiddenNetworks to be parsed as argument
type CIDRList []*net.IPNet

func (xs CIDRList) Len() int {
	return len(xs)
}

func (xs CIDRList) Swap(i int, j int) {
	xs[i], xs[j] = xs[j], xs[i]
}

func (xs CIDRList) Less(i int, j int) bool {
	if len(xs[i].IP) != len(xs[j].IP) {
		return len(xs[i].IP) < len(xs[j].IP)
	}

	for k := 0; k < len(xs[i].IP); k++ {
		if xs[i].Mask[k] != xs[j].Mask[k] {
			return xs[i].Mask[k] < xs[j].Mask[k]
		}
	}

	for k := 0; k < len(xs[i].IP); k++ {
		if xs[i].IP[k] != xs[j].IP[k] {
			return xs[i].IP[k] < xs[j].IP[k]
		}
	}

	return false
}

// Is quite dump. Does not detect IPv4 embedding in IPv6, etc.
func networkContainsOther(network *net.IPNet, other *net.IPNet) bool {
	if len(network.IP) != len(other.IP) {
		return false
	}

	for i := 0; i < len(network.IP); i++ {
		// other might have more bits in the mask set, but network not.
		if network.Mask[i]|other.Mask[i] != other.Mask[i] {
			return false
		}

		maskedNetwork := network.IP[i] & network.Mask[i]
		maskedOther := other.IP[i] & network.Mask[i]

		if maskedNetwork != maskedOther {
			return false
		}
	}

	return true
}

// This function assumes that no network in forbiddenNetworks contains another.
// This function makes sure that this is true after adding the new network.
func (forbiddenNetworks *CIDRList) addNetwork(network *net.IPNet) {
	// Try to find out, whether some network contains the new one or other way round
	newForbiddenNetworks := CIDRList{}

	for _, n := range *forbiddenNetworks {
		if networkContainsOther(n, network) {
			// No change needed
			return
		} else if !networkContainsOther(network, n) {
			newForbiddenNetworks = append(newForbiddenNetworks, n)
		}
	}

	newForbiddenNetworks = append(newForbiddenNetworks, network)

	*forbiddenNetworks = newForbiddenNetworks
}

func (forbiddenNetworks *CIDRList) String() string {
	strs := []string{}

	for _, ipnet := range *forbiddenNetworks {
		strs = append(strs, ipnet.String())
	}

	return strings.Join(strs, ", ")
}

func (forbiddenNetworks *CIDRList) Set(value string) error {
	ipnet, err := parseIPOrCIDR(value)

	if err == nil {
		forbiddenNetworks.addNetwork(ipnet)
	}

	return err
}

// Blocks known local networks and all networks currently known to all interfaces.
// This is only somewhat effective, as the known networks can change later on.
func (forbiddenNetworks *CIDRList) blockLocalNetworks() {
	interfaceAddrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalln("Getting of used IPs failed!")
	}

	for _, blockedNetwork := range interfaceAddrs {
		ipnet, err := parseIPOrCIDR(blockedNetwork.String())

		if err != nil {
			log.Fatalln("Parsing of local network/IP " + blockedNetwork.String() + " failed. That should never happen.")
		}

		forbiddenNetworks.addNetwork(ipnet)
	}

	// We still block networks from a list, since the user might add networks
	// after bugzillatoatom is started
	for _, blockedNetwork := range blockedLocalNetworks {
		ipnet, err := parseIPOrCIDR(blockedNetwork)

		if err != nil {
			log.Fatalln("Parsing of integrated network " + blockedNetwork + " failed. That should never happen.")
		}

		forbiddenNetworks.addNetwork(ipnet)
	}
}

// Sets the http.DefaultClient to a client with timeout which
// blocks connections to a host with an IP in forbiddenNetworks
func setHttpDefaultClient(forbiddenNetworks []*net.IPNet) {
	// Copy the original DefaultTransport and add our dialer
	httpDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	httpTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host := addr
		port := ""
		portPosition := strings.LastIndex(addr, ":")
		bracketPosition := strings.LastIndex(addr, "]")

		// Strip port and brackets, targetAllowedIps/net.LookupIP needs it that way.
		// This comparison also works if one or both are not found
		if portPosition > bracketPosition {
			if bracketPosition == -1 {
				port = addr[portPosition:]
				host = addr[:portPosition]
			} else {
				port = addr[portPosition:]
				host = addr[1 : portPosition-1]
			}
		} else {
			if bracketPosition != -1 {
				host = addr[1 : len(addr)-2]
			}
		}

		ips, err := targetAllowedIPs(host, forbiddenNetworks)

		if err != nil {
			return nil, err
		}

		for _, ip := range ips {
			var ipstr string

			if len(ip.To4()) == net.IPv4len {
				ipstr = ip.String() + port
			} else {
				ipstr = "[" + ip.String() + "]" + port
			}

			conn, err := httpDialer.DialContext(ctx, network, ipstr)

			if err == nil {
				return conn, nil
			}
		}

		return nil, errors.New("Unable to connect to " + addr)
	}

	// Add a timeout for the default http.Get() in case something goes wrong
	// on the other side.
	http.DefaultClient = &http.Client{
		Timeout:   time.Second * 30,
		Transport: httpTransport,
	}
}

func main() {
	version := flag.Bool("version", false, "Print the current version and exit.")
	port := flag.Uint64("p", 33916, "Port to bind to.")
	maxBugRequestReadFlag := flag.Uint64("requestsize", 1*1024*1024, "Maximum number of bytes to read during a request to another server.") // 1MiB per default
	flag.IntVar(&maxRequestsPerSecond, "persecond", 5, "Maximum number of requests to another server per second. Set to -1 to disable.")
	forbiddenNetworks := CIDRList{}
	flag.Var(&forbiddenNetworks, "b", "IP or network in CIDR format to block. If a host is available under any blocked IP it will be blocked. Can be given multiple times.\n\tYou probably want to exclude localhost or local networks both on IPv4 and IPv6. These are blocked by default unless you give -nolocalblock.")
	nolocalblock := flag.Bool("nolocalblock", false, "Disables default blocking of local networks and IPs. If this flag is given you can add those again via -b.\n\tThis includes all IPs and networks of local interfaces and the networks "+strings.Join(blockedLocalNetworks, ", ")+".")
	flag.Parse()

	if *version {
		log.Fatalln(getVersion())
	}

	if *maxBugRequestReadFlag&(1<<63) != 0 {
		log.Fatalln("Too large requestsize")
	} else {
		maxBugRequestRead = int64(*maxBugRequestReadFlag)
	}

	// Block local networks + IPs
	if !(*nolocalblock) {
		forbiddenNetworks.blockLocalNetworks()
	}

	sort.Sort(forbiddenNetworks)

	for _, ipnet := range forbiddenNetworks {
		log.Printf("Network %s blocked\n", ipnet)
	}

	setHttpDefaultClient(forbiddenNetworks)

	if maxRequestsPerSecond >= 0 {
		throttler = throttling.NewThrottler(uint(maxRequestsPerSecond))
	}

	server := http.Server{
		ReadTimeout: 30 * time.Second,
		Addr:        ":" + strconv.FormatUint(*port, 10),
	}

	// Disable keepalives, as they can interfere with the CloseNotifier interface (as of 2017-02-09)
	server.SetKeepAlivesEnabled(false)
	http.HandleFunc("/convert", handleConvert)
	http.HandleFunc("/", handleMain)

	log.Fatal(server.ListenAndServe())
}
