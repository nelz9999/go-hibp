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

package hibp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const minResultLines = 381
const maxResultLines = 584

const data = `
00000000000000000000000000000000000:13
0018A45C4D1DEF81644B54AB7F969B88D65:229
01010101010101010101010101010101010:17
012A7CA357541F0AC487871FEEC1891C49C:401
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:23
`

func TestFind(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(data))
	}))
	defer ts.Close()

	f := NewFinder(
		WithClient(ts.Client()),
		WithURLTemplate(fmt.Sprintf("%s/%%s", ts.URL)),
	)

	testCases := []struct {
		pwd string
		exp int64
	}{
		{
			"melobie",
			401,
		},
		{
			"gonna-miss",
			0,
		},
		{
			"lauragpe",
			229,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.pwd, func(t *testing.T) {
			h := sha1.Sum([]byte(tc.pwd))
			n, err := f.Find(h[:])
			if err != nil {
				t.Errorf("unexpected: %v\n", err)
			}
			if n != tc.exp {
				t.Errorf("expected %d: %d\n", tc.exp, n)
			}
		})
	}
}

func TestFindErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429) // Throttled
	}))
	defer ts.Close()

	f := &Finder{
		conn: ts.Client(),
		tmpl: fmt.Sprintf("%s/%%s", ts.URL),
	}

	alpha := []byte("abcdefghijklmnopqrstuvwxyz")

	testCases := []struct {
		name string
		buf  []byte
		xErr string
	}{
		{
			"too short",
			alpha[:19],
			io.ErrShortBuffer.Error(),
		},
		{
			"too long",
			alpha[:21],
			io.ErrShortWrite.Error(),
		},
		{
			"right size but throttled",
			alpha[:20],
			"429",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := f.Find(tc.buf)
			if n != 0 || err == nil {
				t.Errorf("expected [0, err]: %d, %v\n", n, err)
			}
			if !strings.Contains(err.Error(), tc.xErr) {
				t.Errorf("expected %q: %v\n", tc.xErr, err)
			}
			// t.Logf("%v\n", err)
		})
	}
}

func TestIntegrationFetch(t *testing.T) {
	// Per (https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange)
	// The docs say EVERY valid 5-character hex string will return a 200,
	// with at least 381 lines returned, and at most 584
	if testing.Short() {
		t.Skipf("skip integration test in short mode")
	}

	b := make([]byte, 3)
	rand.Read(b)
	prefix := []byte(fmt.Sprintf("%5X", b))[:prefixSize]

	f := NewFinder()
	body, err := f.fetchPrefix(prefix)
	if err != nil {
		t.Errorf("unexpected: %v\n", err)
	}

	verbose := os.Getenv("VERBOSE") != ""
	size := 0
	buf := bufio.NewReader(bytes.NewReader(body))
	for {
		buf, _, err := buf.ReadLine()
		if err != nil {
			if err != io.EOF {
				t.Logf("Error: %v\n", err)
			}
			break
		}
		size++
		if verbose {
			t.Logf("%s\n", buf)
		}
	}
	if size < minResultLines {
		t.Errorf("expected min %d lines: %d\n", minResultLines, size)
	}
	if size > maxResultLines {
		t.Errorf("expected max %d lines: %d\n", maxResultLines, size)
	}
	t.Logf("Prefix: %s; Size: %d\n", prefix, size)
}

func TestParseCount(t *testing.T) {
	testCases := []struct {
		name   string
		body   string
		exErr  bool
		result int64
	}{
		{
			"empty",
			"",
			true,
			0,
		},
		{
			"no delim",
			"hubba",
			true,
			0,
		},
		{
			"too many delim",
			"::",
			true,
			0,
		},
		{
			"empty number",
			"alpha:",
			true,
			0,
		},
		{
			"string is not number",
			"alpha:bravo",
			true,
			0,
		},
		{
			"simple number",
			"alpha:117",
			false,
			117,
		},
		{
			"big number",
			"alpha:2345678901",
			false,
			2345678901,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := parseCount([]byte(tc.body))
			if tc.exErr && err == nil {
				t.Errorf("expected error")
			}
			if n != tc.result {
				t.Errorf("expected %d: %d\n", tc.result, n)
			}
		})
	}
}

const scanContent = `
alpha:0
beta:1
gamma:2
delta:3
`

func TestFindSuffix(t *testing.T) {
	testCases := []struct {
		name   string
		suffix string
		r      io.Reader
		xOut   string
	}{
		{
			"found",
			"alpha",
			strings.NewReader(scanContent),
			"alpha:0",
		},
		{
			"omitted",
			"omega",
			strings.NewReader(scanContent),
			"",
		},
		{
			"not prefix",
			"amma",
			strings.NewReader(scanContent),
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := findSuffix([]byte(tc.suffix), tc.r)
			if err != nil {
				t.Fatalf("unexpected: %v\n", err)
			}
			out := string(r)
			if tc.xOut != out {
				t.Errorf("expected %q: %q\n", tc.xOut, out)
			}
		})
	}
}
