package main

import "bufio"
import "io"
import "bytes"
import "fmt"
import "strings"
import "errors"

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
			return "", errors.New(fmt.Sprintf("Error during reading from url: %s", err))
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
