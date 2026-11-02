package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// Single request path for target probes. Every live request in the engine goes
// through doBounded, so the safety properties are decided once: SSRF guard,
// bounded read, no redirect following, and one shared non-destructive client.

// nonDestructiveClient is the client used for all target probes. It does not
// follow redirects (a probe must never land its payload on a host the operator
// did not authorize) and accepts self-signed certificates because the engine
// assesses the certificate itself. Whether a request mutates state is the
// caller's decision — see doBounded.
func nonDestructiveClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // we assess the cert ourselves
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// joinBase appends p to base without doubling or dropping the separator. Use it
// for every base-relative probe URL instead of hand-rolling TrimRight.
func joinBase(base, p string) string { return strings.TrimRight(base, "/") + p }

// doBounded performs one SSRF-guarded request through nonDestructiveClient and
// returns status, headers and a bounded body. An empty body sends no payload
// (GET/HEAD); a non-empty body is sent as JSON.
func doBounded(method, url, body string, maxBytes int64) (int, http.Header, string, bool) {
	if err := ssrfSafeURL(url); err != nil {
		return 0, nil, "", false
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, nil, "", false
	}
	req.Header.Set("User-Agent", userAgent)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := nonDestructiveClient().Do(req)
	if err != nil {
		return 0, nil, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return resp.StatusCode, resp.Header, string(b), true
}

// getWithBody performs a guarded non-destructive GET (see doBounded).
func getWithBody(url string, maxBytes int64) (int, http.Header, string, bool) {
	return doBounded("GET", url, "", maxBytes)
}

// postJSONBody performs a guarded bounded POST with a JSON body (see doBounded).
func postJSONBody(url, body string, maxBytes int64) (int, string, bool) {
	code, _, resp, ok := doBounded("POST", url, body, maxBytes)
	return code, resp, ok
}
