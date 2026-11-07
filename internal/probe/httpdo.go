package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// Client is one non-destructive request path. Every live request shares its
// safety properties: a Guard decides reachability once, redirects are never
// followed (a probe must not land its payload on an unauthorized host), and
// self-signed certificates are accepted because the engine assesses the
// certificate itself. Whether a request mutates state is the caller's choice of
// method and body.
type Client struct {
	Guard     Guard  // URL-level reachability decision; required
	UserAgent string // sent on every request
	hc        *http.Client
}

// NewClient builds a Client with the shared non-destructive transport. guard is
// required; a nil guard rejects every request (fail closed).
//
// The transport pins a connect-time Control hook that re-checks the resolved
// address with BlockedIP on the actual dial, closing the TOCTOU / DNS-rebinding
// gap between the URL guard and the socket: a hostname that passed the guard
// cannot re-resolve to a loopback/metadata/private address at dial time. When
// allowLocal is true the connect-time check is skipped — used only by a
// self-measurement harness against its own loopback corpus, never on a
// target-facing path.
func NewClient(guard Guard, userAgent string, allowLocal bool) *Client {
	return newClient(guard, userAgent, allowLocal, false)
}

// NewVerifyingClient is like NewClient but verifies the server's TLS certificate
// (default tls.Config). Use it whenever we SEND data rather than assess a target:
// delivering a tenant feed to a webhook must not travel over a connection a MITM
// can read, so skipping cert verification (right for banner-grabbing a target we
// are judging) is wrong here. The SSRF dial guard and no-redirect policy are kept.
func NewVerifyingClient(guard Guard, userAgent string, allowLocal bool) *Client {
	return newClient(guard, userAgent, allowLocal, true)
}

func newClient(guard Guard, userAgent string, allowLocal, verifyTLS bool) *Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	dialer.Control = func(_, address string, _ syscall.RawConn) error {
		if allowLocal {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("blocked address: %q", address)
		}
		ip := net.ParseIP(host)
		if ip == nil || BlockedIP(ip) {
			return fmt.Errorf("blocked address: %s", host)
		}
		return nil
	}
	// Scanning assesses the cert itself, so it skips verification; sending data
	// (verifyTLS) must use the default verifying tls.Config.
	tlsCfg := &tls.Config{InsecureSkipVerify: true} // we assess the cert ourselves
	if verifyTLS {
		tlsCfg = &tls.Config{}
	}
	return &Client{
		Guard:     guard,
		UserAgent: userAgent,
		hc: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				Proxy:           nil, // never honor a proxy that could bypass the dial guard
				DialContext:     dialer.DialContext,
				TLSClientConfig: tlsCfg,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// JoinBase appends p to base without doubling or dropping the separator.
func JoinBase(base, p string) string { return strings.TrimRight(base, "/") + p }

// DoBounded performs one guarded request and returns status, headers, and a
// body bounded to maxBytes. An empty body sends no payload (GET/HEAD); a
// non-empty body is sent as JSON. ok is false on any guard rejection, build,
// transport, or connect-time address-block error.
func (c *Client) DoBounded(method, url, body string, maxBytes int64) (int, http.Header, string, bool) {
	if c.Guard == nil || c.Guard(url) != nil {
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
	req.Header.Set("User-Agent", c.UserAgent)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return resp.StatusCode, resp.Header, string(b), true
}

// GetWithBody performs a guarded non-destructive GET.
func (c *Client) GetWithBody(url string, maxBytes int64) (int, http.Header, string, bool) {
	return c.DoBounded("GET", url, "", maxBytes)
}

// GetWithBasicAuth performs a guarded GET with an HTTP Basic credential. It is
// read-only (GET), shares the guard and connect-time address check, and exists
// for authorized default-credential exposure checks; the credential is never
// logged by this package.
func (c *Client) GetWithBasicAuth(url, user, pass string, maxBytes int64) (int, http.Header, string, bool) {
	if c.Guard == nil || c.Guard(url) != nil {
		return 0, nil, "", false
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil, "", false
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.SetBasicAuth(user, pass)
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return resp.StatusCode, resp.Header, string(b), true
}

// PostJSONBody performs a guarded bounded POST with a JSON body.
func (c *Client) PostJSONBody(url, body string, maxBytes int64) (int, string, bool) {
	code, _, resp, ok := c.DoBounded("POST", url, body, maxBytes)
	return code, resp, ok
}
