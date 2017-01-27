package main

import "strings"
import "strconv"
import "fmt"
import "errors"
import "net"
import "net/http"
import "net/url"
import "time"
import "html"
import "log"
import "io"
import "bufio"
import "bytes"
import "flag"
import "encoding/xml"
import "golang.org/x/tools/blog/atom"


// Maximum size a request for a bug-xml is read in byte. 
var maxBugRequestRead int64

// Maximum number of requests per second. Set to something negative to disable
var maxRequestsPerSecond int

// Channel to block on during too many requests in a second
var tooManyRequestsBlocker chan bool = make(chan bool)

const bugzillaDateFormat = "2006-01-02 15:04:05 -0700"


// returns the minimum of the given values
func min(a int, b int) int {
    if a <= b {
        return a
    } else {
        return b
    }
}

// Read from r until given string is found. Appends toAppend afterwards if string
// is found and in any case returns the result
func readUntilString(r io.Reader, until string, toAppend string) (string, error) {
    var buffer bytes.Buffer
    eofReached := false
    rs := bufio.NewReader(io.LimitReader(r, maxBugRequestRead))

    for !eofReached {
        str, err := rs.ReadString('\n')

        if err == io.EOF {
            eofReached = true
        } else if err != nil {
            log.Printf("Error during reading from url: %s\n", err)
            return "", err
        }

        index := strings.Index(str, until)

        if index == -1 {
            buffer.WriteString(str)
        } else {
            buffer.WriteString(str[:index])
            buffer.WriteString(toAppend)
            break
        }
    }

    return buffer.String(), nil
}

// Requests the bug from given url
func doRequest(target string) (string, error) {
    resp, err := http.Get(target)

    if err != nil {
        log.Printf("Error during GET to url \"%s\": %s\n", target, err)
        return "", err
    }

    defer resp.Body.Close()

    // TODO: maybe we should search for something more clever to abort. <attachment could be given by a user in a report
    return readUntilString(resp.Body, "<attachment", "</bug></bugzilla>")
}

// converts the given xml string into an atom feed
func convertXmlToAtom(inXml string) (string, error) {
    type Who struct {
        Name string `xml:",chardata"`
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
        CommentId int `xml:"commentid"`
        CommentCount int `xml:"comment_count"`
        AttachmentID int `xml:"attachid"`
        Who Who `xml:"who"`
        When string `xml:"bug_when"`
        Text string `xml:"thetext"`
    }

    type InResult struct {
        Urlbase string `xml:"urlbase,attr"`
        BugId int `xml:"bug>bug_id"`
        Description string `xml:"bug>short_desc"`
        Comments []Comment `xml:"bug>long_desc"`
    } 

    inResult := InResult{}
    err := xml.Unmarshal([]byte(inXml), &inResult)
    if err != nil {
        log.Printf("Error during unmarshalling the xml: %s\n", err)
        return "", err
    } else if len(inResult.Comments) == 0 {
        // One comment, the initial one, should always be available
        err := errors.New("Zero comments in bug. There should be at least the initial one.")
        log.Printf("Error after unmarshalling the xml: %s\n", err)
        return "", err
    }

    updateTime, err := time.Parse(bugzillaDateFormat, inResult.Comments[len(inResult.Comments)-1].When)
    if err != nil {
        log.Printf("Couldn't parse updateTime in initial comment: %s\n", err)
        return "", err
    }

    inUrl := fmt.Sprintf("%s/show_bug.cgi?id=%d", inResult.Urlbase, inResult.BugId)
    attachmentUrl := fmt.Sprintf("%s/attachment.cgi?id=", inResult.Urlbase)

    feed := &atom.Feed{
        Title: inResult.Description,
        ID: inUrl,
        Link: []atom.Link{atom.Link{Href: inUrl, Rel: "alternate"}},
        Updated: atom.Time(updateTime),
        Author: &atom.Person{Name: getFormatedName(inResult.Comments[0].Who)},
        Entry: make([]*atom.Entry, 0, len(inResult.Comments)),
    }

    for i, comment := range inResult.Comments {
        creationTime, err := time.Parse(bugzillaDateFormat, comment.When)
        if err != nil {
            log.Printf("Couldn't parse updateTime in comment %d: %s\n", i, err)
            return "", err
        }

        links := []atom.Link{atom.Link{Href: inUrl + "#c" + strconv.Itoa(comment.CommentCount), Rel: "alternate"}}
        if comment.AttachmentID != 0 {
            links = append(links, atom.Link{Href: attachmentUrl + strconv.Itoa(comment.AttachmentID), Rel: "enclosure"})
        }

        entry := &atom.Entry{
            Title: getFormatedName(comment.Who) + ": " + comment.Text[:min(100, len(comment.Text))],
            ID: inUrl + "#c" + strconv.Itoa(comment.CommentCount),
            Link: links,
            Published: atom.Time(creationTime),
            Author: &atom.Person{Name: getFormatedName(comment.Who)},
            Content: &atom.Text{Type: "html", Body: strings.Replace(html.EscapeString(comment.Text), "\n", "<br>", -1)},
        }

        feed.Entry = append(feed.Entry, entry)
    }


    atom, err := xml.MarshalIndent(feed, "", "\t")
    if err != nil {
        log.Printf("Error during creating the atom feed: %s\n", err)
        return "", err
    }

    return xml.Header + string(atom), nil
}

// Filters not allowed targets, defined by the given networks
// TODO: Technically an attack is possible. First return a harmless IP
//       for the check and another one later for the actual request.
func checkTargetAllowed(target string, forbiddenNetworks []*net.IPNet) (bool, error) {
    if forbiddenNetworks == nil {
        return true, nil
    }

    ips, err := net.LookupIP(target)

    if err != nil {
        return false, err
    }

    for _, ip := range ips {
        for _, ipnet := range forbiddenNetworks {
            if ipnet.Contains(ip) {
                return false, nil
            }
        }
    }

    return true, nil
}

func handleConvert(w http.ResponseWriter, r *http.Request, forbiddenNetworks []*net.IPNet) {
    // Block during too many requests in the last second
    if maxRequestsPerSecond >= 0 {
        <-tooManyRequestsBlocker
    }

    formValueUrl := r.FormValue("url")

    // if the user didn't give a protocol simply assume http
    if !(strings.HasPrefix(formValueUrl, "http://") || strings.HasPrefix(formValueUrl, "https://")) {
        formValueUrl = "http://" + formValueUrl
    }

    target, err := url.Parse(formValueUrl)

    if err != nil {
        errStr := fmt.Sprintf("Error occurred during parsing the url \"%s\": %s\nAre you sure the url is correct?", r.FormValue("url"), err.Error())
        http.Error(w, errStr, http.StatusInternalServerError)
        return
    }

    parsedQuery := target.Query()
    parsedQuery.Set("ctype", "xml")
    target.RawQuery = parsedQuery.Encode()
    target.Fragment = ""

    if target.Host == "" {
        errStr := fmt.Sprintf("Error occurred during parsing the url \"%s\": No host recognized.\nAre you sure the url is correct?", formValueUrl)
        http.Error(w, errStr, http.StatusInternalServerError)
        return
    }

    allowed, err := checkTargetAllowed(target.Host, forbiddenNetworks)
    if err != nil {
        errStr := fmt.Sprintf("Error occurred during checking the host \"%s\" is blocked.\nAre you sure the url is correct?", target.Host)
        http.Error(w, errStr, http.StatusInternalServerError)
        return
    }

    if !allowed {

        errStr := fmt.Sprintf("Host \"%s\" of url \"%s\" is blocked.", target.Host, formValueUrl)
        http.Error(w, errStr, http.StatusForbidden)
        return
    }

    inXml, err := doRequest(target.String())
    if err != nil {
        errStr := fmt.Sprintf("Error occurred during fetching the url \"%s\": %s\nAre you sure the url is correct?", target.String(), err.Error())
        http.Error(w, errStr, http.StatusInternalServerError)
        return
    }

    atom, err := convertXmlToAtom(inXml)
    if err != nil {
        errStr := fmt.Sprintf("Error occurred during conversion of the url \"%s\" to atom: %s\nAre you sure the url is correct?", target.String(), err.Error())
        http.Error(w, errStr, http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "%s", atom)
}

func handleMain(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "%s", `
<html>
<head>
<title>bugzillatoatom</title>
</head>
<body bgcolor="#FFFFFF">
<form action=convert>
    Convert a Bugzilla bug entry into an Atom feed. Enter an url:
    <input type="text" name="url">
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
        *forbiddenNetworks = append(*forbiddenNetworks, ipnet)
    }

    return err
}

func main() {
    port := flag.Uint64("p", 9080, "Port to bind to")
    maxBugRequestReadFlag := flag.Uint64("requestsize", 1 * 1024 * 1024, "Maximum number of bytes to read during a request to another server.") // 1MiB per default
    flag.IntVar(&maxRequestsPerSecond, "persecond", 1 * 1024 * 1024, "Maximum number of requests to another server per second. Set to -1 to disable.")
    forbiddenNetworks := CIDRList{}
    flag.Var(&forbiddenNetworks, "b", "IP or Network in CIDR format to block. If a host is available under any blocked IP it will be blocked. Can be given multiple times.")
    flag.Parse()

    if *maxBugRequestReadFlag & (1 << 63) != 0 {
        log.Fatal("Too large requestsize")
    } else {
        maxBugRequestRead = int64(*maxBugRequestReadFlag)
    }

    // Add a timeout for the default http.Get() in case something goes wrong
    // on the oher side.
    http.DefaultClient = &http.Client{Timeout: time.Second * 30}

    for i := 0; i < maxRequestsPerSecond; i++ {
        go func() {
            for {
                tooManyRequestsBlocker <- true
                time.Sleep(time.Second)
            }
        }()
    }

    http.HandleFunc("/convert", func(w http.ResponseWriter, r *http.Request) { handleConvert(w, r, forbiddenNetworks) })
    http.HandleFunc("/", handleMain)

    log.Fatal(http.ListenAndServe(":" + strconv.FormatUint(*port, 10), nil))
}