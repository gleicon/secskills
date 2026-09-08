package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Active edge tests (adversarial-readonly): direct-to-origin reachability and
// trusted-header access-control differentials. Read-only; GET requests only.

// originReach dials a candidate IP directly (TLS SNI + Host = target) and returns
// the raw response. If the origin answers content for the target with no edge
// marker, the edge (CDN/WAF) is bypassed by talking to the origin directly.
func originReach(wd, target, candidateIP string, edge edgeInfo) *Finding {
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", candidateIP+":443",
		&tls.Config{InsecureSkipVerify: true, ServerName: target})
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", target, userAgent)
	raw, _ := io.ReadAll(io.LimitReader(conn, 64*1024))
	resp := string(raw)
	if resp == "" {
		return nil
	}
	statusLine := strings.SplitN(resp, "\r\n", 2)[0]
	lower := strings.ToLower(resp)
	for _, m := range []string{"cf-ray", "x-amz-cf-id", "x-akamai", "x-sucuri", "x-iinfo", "server: cloudflare"} {
		if strings.Contains(lower, m) {
			return nil // still behind the edge, not a direct origin
		}
	}
	appLike := strings.Contains(statusLine, " 200") || strings.Contains(statusLine, " 301") ||
		strings.Contains(statusLine, " 302") || strings.Contains(statusLine, " 401") || strings.Contains(statusLine, " 403")
	if !appLike {
		return nil
	}
	ev := captureEvidence(wd, "edge.origin-exposure@1", target, "http-response", "text/plain",
		"GET https://"+candidateIP+"/ (Host: "+target+")", "redacted",
		[]byte(statusLine+"\n(no edge marker in response headers)"))
	return &Finding{
		Title: "Origin reachable directly, bypassing " + edgeLabel(edge) + " (" + candidateIP + ")",
		Host:  "https://" + target, Severity: "HIGH", Status: "open",
		Confidence: "High", Validation: "behavior-confirmed",
		ObservedEvidence: fmt.Sprintf("Direct TLS to %s with Host: %s returned %q and no edge (%s) marker — the origin answers requests that do not traverse the CDN/WAF.", candidateIP, target, statusLine, edgeLabel(edge)),
		ImpactText:       "Origin exposure defeats edge security controls: WAF rulesets, rate-limiting, DDoS and bot management are all bypassed by connecting to the origin IP directly. Restrict the origin to accept traffic only from the CDN (IP allow-list / authenticated origin pulls / mTLS).",
		EvidenceCmd:      "curl -sk --resolve " + shellQuote(target) + ":443:" + candidateIP + " https://" + target + "/ -I",
		ProbeKind:        "manual", ProbeURL: "https://" + target, EvidenceRefs: []string{ev},
		DetectorID:       "edge.origin-exposure@1", Capabilities: []string{capAuthBoundary, capPublicService},
	}
}

func edgeLabel(e edgeInfo) string {
	parts := []string{}
	if e.CDN != "" {
		parts = append(parts, e.CDN+" (CDN)")
	}
	if e.WAF != "" && e.WAF != e.CDN {
		parts = append(parts, e.WAF+" (WAF)")
	}
	if len(parts) == 0 {
		return "the edge"
	}
	return strings.Join(parts, " / ")
}

// trustedHeaderBypass tests whether a client-supplied trust header flips a
// gated (401/403) response to 200 — the WAF-vs-origin header parser/trust
// differential class. Read-only.
func trustedHeaderBypass(wd, u string, baseCode int) *Finding {
	if baseCode != 401 && baseCode != 403 {
		return nil
	}
	variants := []struct {
		name string
		hdrs map[string]string
	}{
		{"X-Forwarded-For 127.0.0.1", map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{"CF-Connecting-IP spoof", map[string]string{"CF-Connecting-IP": "127.0.0.1"}},
		{"X-Real-IP spoof", map[string]string{"X-Real-IP": "127.0.0.1"}},
		{"True-Client-IP spoof", map[string]string{"True-Client-IP": "127.0.0.1"}},
		{"X-Forwarded-Host internal", map[string]string{"X-Forwarded-Host": "localhost"}},
		{"X-Original-URL /", map[string]string{"X-Original-URL": "/"}},
	}
	for _, v := range variants {
		if err := ssrfSafeURL(u); err != nil {
			return nil
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		for k, val := range v.hdrs {
			req.Header.Set(k, val)
		}
		resp, err := nonDestructiveClient().Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			ev := captureEvidence(wd, "edge.header-acl-bypass@1", u, "http-response", "text/plain",
				"GET "+u+" ["+v.name+"]", "none",
				[]byte(fmt.Sprintf("baseline HTTP %d; with %q -> HTTP 200", baseCode, v.name)))
			return &Finding{
				Title: "Access-control bypass via trusted header (" + v.name + ")", Host: u, Severity: "HIGH", Status: "open",
				Confidence: "Confirmed", Validation: "exploited",
				ObservedEvidence: fmt.Sprintf("Endpoint returned HTTP %d normally; with the %q header it returned HTTP 200 — a client-supplied header alters the access decision (edge/origin trust differential).", baseCode, v.name),
				ImpactText:       "A client-controlled header changes an authorization decision, letting an attacker spoof internal-trust headers to reach protected functionality. Strip inbound X-Forwarded-*/CF-Connecting-IP/True-Client-IP at the edge and never trust them for authorization.",
				EvidenceCmd:      "curl -sk -H '" + v.name + "' " + shellQuote(u),
				ProbeKind:        "status", ProbeURL: u,
				EvidenceRefs:     []string{ev}, DetectorID: "edge.header-acl-bypass@1", Capabilities: []string{capAuthBoundary},
			}
		}
	}
	return nil
}

// runEdgeRecon fingerprints the edge and (adversarial + Shodan) looks for origin
// leaks via favicon-hash / cert-CN pivots.
func runEdgeRecon(wd, target string, prof Profile) (edgeInfo, []Finding) {
	base := "https://" + hostOf(target)
	_, hdr, _, ok := getWithBody(base, 8*1024)
	var edge edgeInfo
	if ok {
		edge = fingerprintEdge(hdr)
	}
	var out []Finding
	if !prof.adversarial() {
		return edge, out
	}
	candidates := map[string]bool{}
	if h, ok := faviconHash(base); ok {
		for _, ip := range shodanSearchIPs(fmt.Sprintf("http.favicon.hash:%d", h), 15) {
			candidates[ip] = true
		}
	}
	for _, ip := range shodanSearchIPs("ssl.cert.subject.CN:"+hostOf(target), 15) {
		candidates[ip] = true
	}
	tested := 0
	for ip := range candidates {
		if tested >= 12 {
			break
		}
		tested++
		if f := originReach(wd, hostOf(target), ip, edge); f != nil {
			out = append(out, *f)
		}
	}
	return edge, out
}

// renderEdgeMap renders the Edge & Defense Map report section.
func renderEdgeMap(wd, target string) string {
	base := "https://" + hostOf(target)
	_, hdr, _, ok := getWithBody(base, 8*1024)
	if !ok {
		return "_Edge could not be fingerprinted (primary host unreachable)._"
	}
	edge := fingerprintEdge(hdr)
	var b strings.Builder
	b.WriteString("| Property | Value |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| CDN | %s |\n", orDash(edge.CDN)))
	b.WriteString(fmt.Sprintf("| WAF | %s |\n", orDash(edge.WAF)))
	b.WriteString(fmt.Sprintf("| Via | %s |\n", orDash(edge.Via)))
	if h, ok := faviconHash(base); ok {
		b.WriteString(fmt.Sprintf("| favicon mmh3 (Shodan pivot) | `%d` |\n", h))
	}
	b.WriteString("\n_The favicon hash and certificate CN can be searched on Shodan/Censys (`http.favicon.hash:<h>`, `ssl.cert.subject.CN:<host>`) to enumerate every IP presenting this identity — the looking glass for origin IPs that answer directly and bypass the edge. Origin-bypass findings, if any, are listed among the findings above._")
	return b.String()
}
