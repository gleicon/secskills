package engine

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/textutil"
)

// Active edge tests (adversarial-readonly): direct-to-origin reachability and
// trusted-header access-control differentials. Read-only; GET requests only.

// originReach dials a candidate IP directly (TLS SNI + Host = target). It only
// reports an origin bypass when THREE guards hold, to keep false positives near
// zero: (1) an edge (CDN/WAF) was actually fingerprinted — otherwise there is
// nothing to bypass; (2) the direct response has no edge marker; (3) the direct
// content matches the through-edge baseline (same <title>), proving it is the
// same application, not a catch-all/default 200. `wantTitle` is the baseline
// title fetched through the edge (empty disables origin-bypass reporting).
func originReach(wd, target, candidateIP string, edge EdgeInfo, wantTitle string) *finding.Finding {
	if wantTitle == "" {
		return nil // no reliable content signature -> do not claim a bypass
	}
	advProbe("origin-lookingglass", 1)
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", candidateIP+":443",
		&tls.Config{InsecureSkipVerify: true, ServerName: target})
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", target, fetch.UserAgent)
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
	if !strings.Contains(statusLine, " 200") {
		return nil // require a real app response to compare content
	}
	// content-signature guard: the direct response must carry the SAME page title
	// as the through-edge baseline, else this IP is a different/catch-all server.
	gotTitle := title(bodyOf(resp))
	if gotTitle == "" || !strings.EqualFold(strings.TrimSpace(gotTitle), strings.TrimSpace(wantTitle)) {
		return nil
	}
	advHit("origin-lookingglass")
	// strongest same-origin proof: does the candidate serve the SAME leaf cert?
	certMatch, certSHA := sameLeafCert(target, candidateIP)
	certNote := "page title matched the through-edge baseline"
	if certMatch {
		certNote = "SAME leaf certificate (sha256 " + certSHA[:16] + "...) AND page title matched — high-confidence origin"
	}
	ev := finding.CaptureEvidence(wd, "edge.origin-exposure@1", target, "http-response", "text/plain",
		"GET https://"+candidateIP+"/ (Host: "+target+")", "redacted",
		[]byte(statusLine+"\n"+certNote+"\n(no edge marker in response headers)"))
	return &finding.Finding{
		Title: "Origin reachable directly, bypassing " + edgeLabel(edge) + " (" + candidateIP + ")",
		Host:  "https://" + target, Severity: "HIGH", Status: "open",
		Confidence: certConfidence(certMatch), Validation: "behavior-confirmed",
		ObservedEvidence: fmt.Sprintf("Direct TLS to %s with Host: %s returned %q, no edge (%s) marker; %s — the origin answers requests that do not traverse the CDN/WAF.", candidateIP, target, statusLine, edgeLabel(edge), certNote),
		ImpactText:       "Origin exposure defeats edge security controls: WAF rulesets, rate-limiting, DDoS and bot management are all bypassed by connecting to the origin IP directly. Restrict the origin to accept traffic only from the CDN (IP allow-list / authenticated origin pulls / mTLS).",
		EvidenceCmd:      "curl -sk --resolve " + netsec.ShellQuote(target) + ":443:" + candidateIP + " https://" + target + "/ -I",
		ProbeKind:        "manual", ProbeURL: "https://" + target, EvidenceRefs: []string{ev},
		DetectorID: "edge.origin-exposure@1", Capabilities: []string{finding.CapAuthBoundary, finding.CapPublicService},
	}
}

// bodyOf splits an HTTP response into its body (after the header/body separator).
func bodyOf(resp string) string {
	if i := strings.Index(resp, "\r\n\r\n"); i >= 0 {
		return resp[i+4:]
	}
	return resp
}

func edgeLabel(e EdgeInfo) string {
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
func trustedHeaderBypass(wd, u string, baseCode int) *finding.Finding {
	if baseCode != 401 && baseCode != 403 {
		return nil
	}
	advProbe("header-acl-bypass", 1)
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
		if err := netsec.SSRFSafeURL(u); err != nil {
			return nil
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", fetch.UserAgent)
		for k, val := range v.hdrs {
			req.Header.Set(k, val)
		}
		resp, err := fetch.NonDestructiveClient().Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			advHit("header-acl-bypass")
			ev := finding.CaptureEvidence(wd, "edge.header-acl-bypass@1", u, "http-response", "text/plain",
				"GET "+u+" ["+v.name+"]", "none",
				[]byte(fmt.Sprintf("baseline HTTP %d; with %q -> HTTP 200", baseCode, v.name)))
			return &finding.Finding{
				Title: "Access-control bypass via trusted header (" + v.name + ")", Host: u, Severity: "HIGH", Status: "open",
				Confidence: "Confirmed", Validation: "exploited",
				ObservedEvidence: fmt.Sprintf("Endpoint returned HTTP %d normally; with the %q header it returned HTTP 200 — a client-supplied header alters the access decision (edge/origin trust differential).", baseCode, v.name),
				ImpactText:       "A client-controlled header changes an authorization decision, letting an attacker spoof internal-trust headers to reach protected functionality. Strip inbound X-Forwarded-*/CF-Connecting-IP/True-Client-IP at the edge and never trust them for authorization.",
				EvidenceCmd:      "curl -sk -H '" + v.name + "' " + netsec.ShellQuote(u),
				ProbeKind:        "status", ProbeURL: u,
				EvidenceRefs: []string{ev}, DetectorID: "edge.header-acl-bypass@1", Capabilities: []string{finding.CapAuthBoundary},
			}
		}
	}
	return nil
}

// RunEdgeRecon fingerprints the edge and (adversarial + Shodan) looks for origin
// leaks via favicon-hash / cert-CN pivots.
func RunEdgeRecon(wd, target string, prof finding.Profile) (EdgeInfo, []finding.Finding) {
	host := netsec.HostOf(target)
	base := "https://" + host
	var edge EdgeInfo
	baseTitle := ""
	// fingerprint the edge from the apex, falling back to www (bare apex often
	// 301s without exposing the CDN headers a real page carries).
	for _, u := range []string{base, "https://www." + host} {
		_, hdr, body, ok := fetch.GetWithBody(u, 32*1024)
		if !ok {
			continue
		}
		e := fingerprintEdge(hdr)
		if e.CDN != "" || e.WAF != "" {
			edge = e
			if t := title(body); t != "" {
				baseTitle = t
			}
			break
		}
		if baseTitle == "" {
			baseTitle = title(body)
		}
	}
	var out []finding.Finding
	if !prof.Adversarial() {
		return edge, out
	}
	// Origin-bypass only makes sense when there IS an edge to bypass. If no CDN/WAF
	// was fingerprinted, direct-IP reachability is expected, not a finding.
	if edge.CDN == "" && edge.WAF == "" {
		return edge, out
	}
	candidates := map[string]bool{}
	if h, ok := faviconHash(base); ok {
		for _, ip := range shodanSearchIPs(fmt.Sprintf("http.favicon.hash:%d", h), 15) {
			candidates[ip] = true
		}
	}
	for _, ip := range shodanSearchIPs("ssl.cert.subject.CN:"+netsec.HostOf(target), 15) {
		candidates[ip] = true
	}
	// widen the net with Censys (key-gated, like Shodan)
	for _, ip := range censysSearchIPs("services.tls.certificates.leaf_data.subject.common_name: "+netsec.HostOf(target), 15) {
		candidates[ip] = true
	}
	tested := 0
	for ip := range candidates {
		if tested >= 12 {
			break
		}
		// skip IPs that are themselves CDN edge nodes (not origin)
		if looksLikeCDN(shodanOrgOf(ip)) {
			continue
		}
		tested++
		if f := originReach(wd, netsec.HostOf(target), ip, edge, baseTitle); f != nil {
			out = append(out, *f)
		}
	}
	return edge, out
}

// RenderEdgeMap renders the Edge & Defense Map report section.
func RenderEdgeMap(wd, target string) string {
	host := netsec.HostOf(target)
	base := "https://" + host
	var edge EdgeInfo
	got := false
	for _, u := range []string{base, "https://www." + host} {
		_, hdr, _, ok := fetch.GetWithBody(u, 8*1024)
		if !ok {
			continue
		}
		got = true
		e := fingerprintEdge(hdr)
		if e.CDN != "" || e.WAF != "" {
			edge = e
			break
		}
		edge = e
	}
	if !got {
		return "_Edge could not be fingerprinted (primary host unreachable)._"
	}
	var b strings.Builder
	b.WriteString("| Property | Value |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| CDN | %s |\n", textutil.OrDash(edge.CDN)))
	b.WriteString(fmt.Sprintf("| WAF | %s |\n", textutil.OrDash(edge.WAF)))
	b.WriteString(fmt.Sprintf("| Via | %s |\n", textutil.OrDash(edge.Via)))
	if h, ok := faviconHash(base); ok {
		b.WriteString(fmt.Sprintf("| favicon mmh3 (Shodan pivot) | `%d` |\n", h))
	}
	b.WriteString("\n_The favicon hash and certificate CN can be searched on Shodan/Censys (`http.favicon.hash:<h>`, `ssl.cert.subject.CN:<host>`) to enumerate every IP presenting this identity — the looking glass for origin IPs that answer directly and bypass the edge. Origin-bypass findings, if any, are listed among the findings above._")
	return b.String()
}

func certConfidence(certMatch bool) string {
	if certMatch {
		return "Confirmed"
	}
	return "High"
}
