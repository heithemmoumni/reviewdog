package main

import (
	"errors"
	"net/http"
	"regexp"
)

// https://github.com/github/codeql-go/blob/a88bf4c9fa495c2b9b3169853c96b89094fcdeed/ql/test/query-tests/Security/CWE-020/MissingRegexpAnchor/MissingRegexpAnchor.go
func checkRedirect2(req *http.Request, via []*http.Request) error {
	// BAD: the host of `req.URL` may be controlled by an attacker
	re := "https?://www\\.example\\.com/"
	if matched, _ := regexp.MatchString(re, req.URL.String()); matched {
		return nil
	}
	return errors.New("Invalid redirect")
}
