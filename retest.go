package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// reprobe re-verifies a finding using its structured probe, entirely in Go — no
// shell, no eval. Returns (stillOpen, testable). testable=false means the finding
// has no automated probe (manual) and its status is left unchanged.
func reprobe(f *Finding) (open bool, testable bool) {
	switch f.ProbeKind {
	case "header-missing":
		h, ok := httpHeaders(f.ProbeURL)
		if !ok {
			return false, true // unreachable now → treat as mitigated
		}
		return h.Get(f.ProbeArg) == "", true
	case "tls-weak":
		return tlsVersionAccepted(hostOf(f.ProbeURL), f.ProbeArg), true
	case "body-contains":
		code, body, ok := httpGetBody(f.ProbeURL)
		if !ok {
			return false, true
		}
		return code == 200 && strings.Contains(body, f.ProbeArg), true
	case "status":
		code, _, ok := httpGetBody(f.ProbeURL)
		if !ok {
			return false, true
		}
		return code == 200, true
	default: // manual / unknown
		return false, false
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
