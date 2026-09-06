package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// nonDestructiveClient is a rate-limited, redirect-capturing HTTP client used for
// all active checks. It never sends state-changing methods.
func nonDestructiveClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // we assess the cert ourselves
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// headParams is the security-header assessment (A05/A02). Returns findings for a
// single URL. Each finding carries a curl evidence command for later retest.
func checkSecurityHeaders(url string) []Finding {
	c := nonDestructiveClient()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	h := resp.Header
	var out []Finding
	n := 0
	add := func(sev, title, header, remediation string) {
		n++
		out = append(out, Finding{
			ID:           fmt.Sprintf("HDR-%02d", n),
			Title:        title,
			Host:         url,
			Severity:     sev,
			Status:       "open",
			EvidenceCmd:  fmt.Sprintf("curl -skI %s | grep -i %q || echo MISSING", shellQuote(url), header),
			ExpectedOpen: "MISSING",
		})
	}
	if h.Get("Strict-Transport-Security") == "" {
		add("LOW", "Missing HSTS header", "strict-transport-security", "kb/crypto-secrets")
	}
	if h.Get("Content-Security-Policy") == "" {
		add("MEDIUM", "Missing Content-Security-Policy", "content-security-policy", "kb/config-exposure")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		add("MEDIUM", "Missing clickjacking protection (X-Frame-Options/frame-ancestors)", "x-frame-options", "kb/config-exposure")
	}
	if h.Get("X-Content-Type-Options") == "" {
		add("LOW", "Missing X-Content-Type-Options: nosniff", "x-content-type-options", "kb/config-exposure")
	}
	if aco := h.Get("Access-Control-Allow-Origin"); aco == "*" {
		add("MEDIUM", "Permissive CORS: Access-Control-Allow-Origin: *", "access-control-allow-origin", "kb/config-exposure")
	}
	return out
}

// checkTLS probes for deprecated TLS 1.0/1.1 acceptance on an https URL (A02).
func checkTLS(url string) []Finding {
	host := hostOf(url)
	if !strings.HasPrefix(url, "https://") {
		return nil
	}
	var out []Finding
	for name, ver := range map[string]uint16{"TLS 1.0": tls.VersionTLS10, "TLS 1.1": tls.VersionTLS11} {
		d := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: ver, MaxVersion: ver},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		conn, err := d.DialContext(ctx, "tcp", host+":443")
		cancel()
		if err == nil {
			conn.Close()
			out = append(out, Finding{
				ID:           "TLS-" + strings.ReplaceAll(name, " ", ""),
				Title:        "Deprecated " + name + " accepted (RFC 8996)",
				Host:         url,
				Severity:     "MEDIUM",
				Status:       "open",
				EvidenceCmd:  fmt.Sprintf("echo | openssl s_client -connect %s:443 -%s 2>/dev/null | grep -q 'Cipher is' && echo ACCEPTED", shellQuote(host), strings.ToLower(strings.ReplaceAll(name, " ", ""))),
				ExpectedOpen: "ACCEPTED",
			})
		}
	}
	return out
}

// exposureSig maps a path to a title and a body signature that must appear for
// the finding to be real (defeats catch-all/SPA 200s).
type exposureSig struct{ title, signature string }

// checkExposure probes common unauthenticated-exposure paths (A05/A09). Read-only.
// It first baselines a random path: if the target returns 200 for nonsense
// (catch-all SPA), a bare 200 on an exposure path proves nothing — the path must
// return a DIFFERENT status than baseline AND/OR match a content signature.
func checkExposure(url string) []Finding {
	c := nonDestructiveClient()
	base := strings.TrimRight(url, "/")
	paths := map[string]exposureSig{
		"/metrics":       {"Prometheus metrics exposed unauthenticated", "# HELP"},
		"/actuator/env":  {"Spring Actuator env exposed", "propertySources"},
		"/debug/pprof/":  {"Go pprof debug endpoint exposed", "profiles"},
		"/.git/config":   {"Exposed .git repository", "[core]"},
		"/server-status": {"Apache server-status exposed", "Apache Server Status"},
	}
	// baseline a random path
	baseCode := 0
	if req, err := http.NewRequest("GET", base+"/secskills-baseline-"+randToken(), nil); err == nil {
		req.Header.Set("User-Agent", userAgent)
		if resp, err := c.Do(req); err == nil {
			baseCode = resp.StatusCode
			resp.Body.Close()
		}
	}
	var out []Finding
	i := 0
	for p, sig := range paths {
		i++
		req, _ := http.NewRequest("GET", base+p, nil)
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		code := resp.StatusCode
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		hasSig := strings.Contains(string(body[:n]), sig.signature)
		// real only if: 200 AND (content signature matches OR status differs from catch-all baseline)
		if code == 200 && (hasSig || baseCode != 200) {
			sev := "HIGH"
			if !hasSig {
				sev = "MEDIUM" // 200 but no signature confirmed — probable, needs eyeball
			}
			out = append(out, Finding{
				ID:           fmt.Sprintf("EXP-%02d", i),
				Title:        sig.title,
				Host:         base + p,
				Severity:     sev,
				Status:       "open",
				EvidenceCmd:  fmt.Sprintf("curl -sk %s | head", shellQuote(base+p)),
				ExpectedOpen: "200",
			})
		}
	}
	return out
}

func randToken() string {
	b := make([]byte, 6)
	crand.Read(b)
	return fmt.Sprintf("%x", b)
}

// checkAuthenticated runs a light authenticated pass on a URL with the supplied
// headers (A01/A07). It confirms the credential is accepted and flags endpoints
// reachable only with authentication for manual IDOR/priv-esc follow-up. Only
// invoked when credentials are provided.
func checkAuthenticated(url string, headers map[string]string) []Finding {
	c := nonDestructiveClient()
	get := func(withAuth bool) int {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", userAgent)
		if withAuth {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
		r, err := c.Do(req)
		if err != nil {
			return 0
		}
		code := r.StatusCode
		r.Body.Close()
		return code
	}
	unauth := get(false)
	auth := get(true)
	var out []Finding
	// credential unlocks a previously-gated endpoint -> authenticated surface to test
	if (unauth == 401 || unauth == 403) && auth >= 200 && auth < 400 {
		f := Finding{
			Title:        "Authenticated access confirmed (gated unauth) — authenticated surface for IDOR/priv-esc testing",
			Host:         url,
			Severity:     "INFORMATIONAL",
			Status:       "open",
			EvidenceCmd:  fmt.Sprintf("curl -sk -o /dev/null -w '%%{http_code}' -H 'Authorization: <redacted>' %s", shellQuote(url)),
			ExpectedOpen: "",
		}
		classify(&f)
		out = append(out, f)
	}
	return out
}
