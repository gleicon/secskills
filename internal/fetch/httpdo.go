package fetch

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/netsec"
)

// Single request path for target probes. Every live request in the engine goes
// through doBounded, so the safety properties are decided once: SSRF guard,
// bounded read, no redirect following, and one shared non-destructive client.

// NonDestructiveClient is the client used for all target probes. It does not
// follow redirects (a probe must never land its payload on a host the operator
// did not authorize) and accepts self-signed certificates because the engine
// assesses the certificate itself. Whether a request mutates state is the
// caller's decision — see doBounded.
// InsecureAuth lets credentialed requests skip TLS verification. Off by
// default; set only by `secskills test --insecure-auth` for targets with
// self-signed certificates the operator has accepted.
var InsecureAuth bool

// CredentialedClient is the client for requests carrying operator credentials
// (bearer tokens, cookies). Unlike NonDestructiveClient it verifies TLS, so a
// MITM on the path cannot harvest the credentials. Redirects are not followed.
func CredentialedClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: InsecureAuth},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NonDestructiveClient is the client for unauthenticated target probes. It
// skips TLS verification on purpose: certificates are assessed as findings, and
// a self-signed or expired cert must not hide the rest of the surface. Never
// send credentials through it; use CredentialedClient.
func NonDestructiveClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // we assess the cert ourselves
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// JoinBase appends p to base without doubling or dropping the separator. Use it
// for every base-relative probe URL instead of hand-rolling TrimRight.
func JoinBase(base, p string) string { return strings.TrimRight(base, "/") + p }

// doBounded performs one SSRF-guarded request through nonDestructiveClient and
// returns status, headers and a bounded body. An empty body sends no payload
// (GET/HEAD); a non-empty body is sent as JSON.
func doBounded(method, url, body string, maxBytes int64) (int, http.Header, string, bool) {
	if err := netsec.SSRFSafeURL(url); err != nil {
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
	req.Header.Set("User-Agent", UserAgent)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := NonDestructiveClient().Do(req)
	if err != nil {
		return 0, nil, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return resp.StatusCode, resp.Header, string(b), true
}

// GetWithBody performs a guarded non-destructive GET (see doBounded).
func GetWithBody(url string, maxBytes int64) (int, http.Header, string, bool) {
	return doBounded("GET", url, "", maxBytes)
}

// PostJSONBody performs a guarded bounded POST with a JSON body (see doBounded).
func PostJSONBody(url, body string, maxBytes int64) (int, string, bool) {
	code, _, resp, ok := doBounded("POST", url, body, maxBytes)
	return code, resp, ok
}

// ReadFull reads up to len(buf) bytes.
func ReadFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil || n == 0 {
			return total, err
		}
	}
	return total, nil
}
