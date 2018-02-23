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

// Package hibp ("Have I beep pwned?") provides a minor go wrapper around
// Troy Hunt's Pwned Passwords k-Anonymity API
package hibp

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/nelz9999/go-hibp/generate/client"
	"github.com/nelz9999/go-hibp/generate/client/operations"
)

const defaultHost = "api.pwnedpasswords.com"
const defaultScheme = "https"
const prefixSize = 5

var delim = []byte(":")

const errMsgFormat = "hibp: problem parsing results"

type finder struct {
	cli  *client.HaveIBeenPwned
	conn *http.Client
}

func (f *finder) Find(sum []byte) (int64, error) {
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

	line, err := findSuffix(full[prefixSize:], strings.NewReader(body))
	if err != nil {
		return 0, err
	}
	if len(line) == 0 {
		return 0, nil
	}
	return parseCount(line)
}

func (f *finder) fetchPrefix(prefix []byte) (string, error) {
	ops := client.Default.Operations
	if f != nil && f.cli != nil {
		ops = f.cli.Operations
	}
	params := operations.NewRangeParams().
		WithHTTPClient(f.conn).
		WithPrefix(string(prefix))
	resp, err := ops.Range(params)
	if err != nil {
		return "", err
	}
	return resp.Payload, nil
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
