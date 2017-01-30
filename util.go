package main

import "bufio"
import "io"
import "bytes"
import "fmt"
import "errors"

// returns the minimum of the given values
func min(a int, b int) int {
	if a <= b {
		return a
	} else {
		return b
	}
}

// Returns an array cotaining the longest real prefix of the string until each position
// in it. For Knuth-Morris-Pratt.
func kmpPrefixes(str string) []int {
	out := make([]int, len(str))

	out[0] = 0
	currentPrefixLen := 0

	for i := 1; i < len(str); i++ {
		for currentPrefixLen > 0 && str[currentPrefixLen] != str[i] {
			currentPrefixLen = out[currentPrefixLen-1]
		}

		if str[currentPrefixLen] == str[i] {
			currentPrefixLen += 1
		}

		out[i] = currentPrefixLen
	}

	return out
}

// Reads until str is found (inclusive)
type readUntilReader struct {
	reader   io.Reader
	str      []byte
	prefixes []int
	strpos   int // Current position in string to align with
	found    bool
}

func newReadUntilReader(reader io.Reader, str string) io.Reader {
	return &readUntilReader{reader, []byte(str), kmpPrefixes(str), 0, false}
}

func (r *readUntilReader) Read(p []byte) (int, error) {
	if r.found {
		return 0, io.EOF
	}

	n, err := r.reader.Read(p)

	// Search via Knuth-Morris-Pratt
	for i := 0; i < n; {
		if p[i] != r.str[r.strpos] {
			if r.strpos == 0 {
				i += 1
			} else {
				r.strpos = r.prefixes[r.strpos-1]
			}
		} else if r.strpos == len(r.str)-1 {
			// Found
			r.found = true
			return i + 1, err
		} else {
			r.strpos += 1
			i += 1
		}
	}

	return n, err
}

// Reads only if str is found in the first count bytes (inclusive).
// Otherwise an error is thrown.
type readContainsStringReader struct {
	reader   io.Reader
	str      []byte
	prefixes []int
	strpos   int // Current position in string to align with
	found    bool
	count    int
	counter  int // counts until count, then an error is thrown
}

func newReadContainsStringReader(reader io.Reader, str string, count int) io.Reader {
	return &readContainsStringReader{reader, []byte(str), kmpPrefixes(str), 0, false, count, 0}
}

func (r *readContainsStringReader) Read(p []byte) (int, error) {
	if r.found {
		return r.reader.Read(p)
	}

	n, err := r.reader.Read(p)

	// Search via Knuth-Morris-Pratt
	for i := 0; i < n; {
		r.counter += 1
		if r.counter > r.count {
			errStr := fmt.Sprintf("Couldn't find string \"%s\" in the first %d bytes.", r.str, r.count)
			return 0, errors.New(errStr)
		}

		if p[i] != r.str[r.strpos] {
			if r.strpos == 0 {
				i += 1
			} else {
				r.strpos = r.prefixes[r.strpos-1]
			}
		} else if r.strpos == len(r.str)-1 {
			// Found
			r.found = true
			return n, err
		} else {
			r.strpos += 1
			i += 1
		}
	}

	return n, err
}

// Read from r until EOF or the given string is found. Appends toAppend afterwards if string
// is found. Also the reader has to contain hasToContain in the
// first hasToContainInBytes bytes or an error is returned.
func readUntilString(r io.Reader, until string, toAppend string, hasToContain string, hasToContainInBytes int) (string, error) {
	var buffer bytes.Buffer
	rs := bufio.NewReader(newReadContainsStringReader(newReadUntilReader(io.LimitReader(r, maxBugRequestRead), until), hasToContain, hasToContainInBytes))

	_, err := buffer.ReadFrom(rs)
	if err != nil {
		return "", err
	}

	str := buffer.String()
	if len(str) >= len(until) && str[len(str)-len(until):] == until {
		str = str[:len(str)-len(until)] + toAppend
	}

	return str, nil
}
