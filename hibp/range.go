// Copyright © 2017 Nelz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Package hibp ("Have I beep pwned?") provides a go wrapper around
// Troy Hunt's Pwned Passwords k-Anonymity API.
//
// See more here:
// https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/ and
// https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange
package hibp

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

const prefixSize = 5

var delim = []byte(":")

const errMsgFormat = "hibp: problem parsing results"

// DefaultTemplate creates URLs pointing to the original Pwned Passwords API
const DefaultTemplate = "https://api.pwnedpasswords.com/range/%s"

// NewFinder returns a new Finder, set up with the options provided.
func NewFinder(options ...func(*Finder)) *Finder {
	f := &Finder{
		tmpl: DefaultTemplate,
		conn: http.DefaultClient,
	}
	for _, opt := range options {
		opt(f)
	}
	return f
}

// WithURLTemplate replaces the DefaultTemplate to build the URL to fetch.
//
// This is useful to retrieve from a different hosted solution.
//
// (It is possible to download and self-host the data, see the "Downloading
// the Data" section at
// https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
func WithURLTemplate(template string) func(f *Finder) {
	return func(f *Finder) {
		f.tmpl = template
	}
}

// WithClient replaces the http.DefaultClient
func WithClient(client *http.Client) func(f *Finder) {
	return func(f *Finder) {
		f.conn = client
	}
}

// Finder looks for reported password breaches.
type Finder struct {
	tmpl string
	conn *http.Client
}

// Find takes the 20 byte output of a sha1.Sum(), and retrieves the count
// of time that the source string has been found in breaches. A zero (without
// an error) means there's no evidence that the given string has had a
// previous breach.
//
// (Some passwords have been breached THOUSANDS of times, most of the entries
// have only been seen a handful of times. It is up to the consumer to decide
// what effect these counts have on your password policy. See the section "Each
// Password Now Has a Count Next to It" at
// https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
//
// The only information sent upstream is the first 5 hex digits of the
// provided SHA1, the rest of the matching is done locally. (For more
// information on why this is, see the section "Cloudflare, Privacy and
// k-Anonymity" at
// https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
func (f *Finder) Find(sum []byte) (int64, error) {
	if len(sum) < sha1.Size {
		return 0, io.ErrShortBuffer
	}
	if len(sum) > sha1.Size {
		return 0, io.ErrShortWrite
	}
	full := []byte(fmt.Sprintf("%X", sum))
	body, err := f.fetchPrefix(full[:prefixSize])
	if err != nil {
		return 0, err
	}

	line, err := findSuffix(full[prefixSize:], bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if len(line) == 0 {
		return 0, nil
	}
	return parseCount(line)
}

func (f *Finder) fetchPrefix(prefix []byte) ([]byte, error) {
	url := fmt.Sprintf(f.tmpl, prefix)
	resp, err := f.conn.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	return ioutil.ReadAll(resp.Body)
}

func findSuffix(suffix []byte, content io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		b := scanner.Bytes()
		if bytes.HasPrefix(b, suffix) {
			return b, nil
		}
	}
	return nil, scanner.Err()
}

func parseCount(line []byte) (int64, error) {
	parts := bytes.Split(line, delim)
	if len(parts) != 2 {
		return 0, fmt.Errorf("%s: %s", errMsgFormat, line)
	}
	return strconv.ParseInt(string(parts[1]), 10, 64)
}
