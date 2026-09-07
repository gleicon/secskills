package main

import (
	"fmt"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// reprobe re-verifies a finding using its structured probe, entirely in Go — no
// shell, no eval. Returns (stillOpen, testable). testable=false means the finding
// has no automated probe (manual) and its status is left unchanged.
// reprobe re-verifies a finding in Go with no shell. It returns a tri-state plus
// the evidence observed this run:
//   "open"          - the weakness is still present
//   "mitigated"     - the weakness is gone (control now present)
//   "inconclusive"  - the host was unreachable/errored, so we cannot assert
//                     either way (never silently counted as fixed)
//   "manual"        - no structured probe; requires human recheck
func reprobe(f *Finding) (state string, evidence string) {
	switch f.ProbeKind {
	case "header-missing":
		h, ok := httpHeaders(f.ProbeURL)
		if !ok {
			return "inconclusive", "host unreachable at retest (" + f.ProbeURL + ")"
		}
		if h.Get(f.ProbeArg) == "" {
			return "open", "header " + f.ProbeArg + " still absent"
		}
		return "mitigated", "header " + f.ProbeArg + " now present: " + redactedSample(h.Get(f.ProbeArg), 80)
	case "tls-weak":
		if f.ProbeArg == "" {
			return "manual", "cipher-only weakness; protocol reprobe not applicable"
		}
		host := hostOf(f.ProbeURL)
		if tlsVersionAccepted(host, f.ProbeArg) {
			return "open", "TLS " + f.ProbeArg + " still accepted on " + host + ":443"
		}
		return "mitigated", "TLS " + f.ProbeArg + " now rejected on " + host + ":443"
	case "body-contains":
		code, body, ok := httpGetBody(f.ProbeURL)
		if !ok {
			return "inconclusive", "host unreachable at retest (" + f.ProbeURL + ")"
		}
		if code == 200 && strings.Contains(body, f.ProbeArg) {
			return "open", "pattern still present (HTTP 200)"
		}
		return "mitigated", fmt.Sprintf("pattern absent (HTTP %d)", code)
	case "status":
		code, _, ok := httpGetBody(f.ProbeURL)
		if !ok {
			return "inconclusive", "host unreachable at retest (" + f.ProbeURL + ")"
		}
		if code == 200 {
			return "open", "endpoint still returns HTTP 200"
		}
		return "mitigated", fmt.Sprintf("endpoint now returns HTTP %d", code)
	default:
		return "manual", "no structured probe; requires human recheck"
	}
}

func httpHeaders(url string) (http.Header, bool) {
	c := nonDestructiveClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, false
	}
	resp.Body.Close()
	return resp.Header, true
}

func httpGetBody(url string) (int, string, bool) {
	c := nonDestructiveClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", false
	}
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	resp.Body.Close()
	return resp.StatusCode, string(buf[:n]), true
}

// tlsVersionAccepted reports whether host:443 still accepts the given deprecated
// TLS version ("1.0" or "1.1").
func tlsVersionAccepted(host, ver string) bool {
	var v uint16
	switch strings.TrimSpace(ver) {
	case "1.0":
		v = tls.VersionTLS10
	case "1.1":
		v = tls.VersionTLS11
	default:
		return false
	}
	d := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: v, MaxVersion: v},
	}
	conn, err := d.Dial("tcp", host+":443")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
