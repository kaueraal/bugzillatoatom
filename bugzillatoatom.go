package main

import "strings"
import "strconv"
import "fmt"
import "errors"
import "net/http"
import "time"
import "html"
import "log"
import "io"
import "bufio"
import "bytes"
import "encoding/xml"
import "golang.org/x/tools/blog/atom"


// TODO that shouldn't be a constant. Parse as argument?
// Maximum size a request for a bug-xml is read in byte. 
var maxBugRequestRead int64 = 1 * 1024 * 1024 // 1MiB per default

// TODO that shouldn't be a constant. Parse as argument?
// Maximum number of requests per second. Set to something negative to disable
var maxRequestsPerSecond int = 5

const bugzillaDateFormat = "2006-01-02 15:04:05 -0700"

// Channel to block on during too many requests in a second
var tooManyRequestsBlocker chan bool = make(chan bool)


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
        // TODO: add attachments?
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

func handleConvert(w http.ResponseWriter, r *http.Request) {
    // TODO: do some security: What about local domains, etc... Is there even an url? Test for this stuff!
    // TODO: Do not always add ctype=xml, do some security checking or so.. Add via function? Also it's broken when only an domain is entered, or domain+port without / at the end
    // TODO: remove anchors as #c0

    // Block during too many requests in the last second
    if maxRequestsPerSecond >= 0 {
        <-tooManyRequestsBlocker
    }

    target := r.FormValue("url") + "&ctype=xml"

    // if the user didn't give a protocol simply assume http
    if !(strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")) {
        target = "http://" + target
    }

    inXml, err := doRequest(target)
    if err != nil {
        errStr := fmt.Sprintf("Error occurred during fetching the url \"%s\": %s\nAre you sure the url is correct?", target, err.Error())
        http.Error(w, errStr, http.StatusInternalServerError)
        return
    }

    atom, err := convertXmlToAtom(inXml)
    if err != nil {
        errStr := fmt.Sprintf("Error occurred during conversion of the url \"%s\" to atom: %s\nAre you sure the url is correct?", target, err.Error())
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
    // TODO: do some pretty gui stuff
}

func main() {
    for i := 0; i < maxRequestsPerSecond; i++ {
        go func() {
            for {
                tooManyRequestsBlocker <- true
                time.Sleep(time.Second)
            }
        }()
    }

    http.HandleFunc("/convert", handleConvert)
    http.HandleFunc("/", handleMain)

    http.ListenAndServe(":9080", nil)
}