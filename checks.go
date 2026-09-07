package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
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
	ct := strings.ToLower(h.Get("Content-Type"))
	isHTML := strings.Contains(ct, "text/html")
	var out []Finding
	n := 0
	add := func(sev, title, header, impact string) {
		n++
		out = append(out, Finding{
			ID:           fmt.Sprintf("HDR-%02d", n),
			Title:        title,
			Host:         url,
			Severity:     sev,
			Status:       "open",
			Confidence:   "Confirmed",   // header absence is directly observed
			Validation:   "passive",     // observed, not exploited
			ImpactText:   impact,
			EvidenceCmd:      fmt.Sprintf("curl -skI %s | grep -i %q || echo MISSING", shellQuote(url), header),
			ExpectedOpen:     "MISSING",
			ObservedEvidence: "Response Content-Type: " + dash(ct) + "; header " + header + " absent from the response headers.",
			ProbeKind:        "header-missing", ProbeURL: url, ProbeArg: header,
		})
	}

	// HSTS: relevant to any https service; low on its own.
	if strings.HasPrefix(url, "https://") && h.Get("Strict-Transport-Security") == "" {
		add("LOW", "Missing HSTS header", "strict-transport-security",
			"Without HSTS a network attacker can strip TLS on the first request; low impact on its own, defense-in-depth for the domain.")
	}

	// CSP / clickjacking: only materially relevant when the response is HTML that a
	// browser renders. On a JSON/API endpoint these are hardening deviations, not
	// clickjacking/XSS-mitigation gaps — rate INFORMATIONAL and mark not-applicable.
	if h.Get("Content-Security-Policy") == "" {
		if isHTML {
			add("LOW", "Missing Content-Security-Policy (HTML response)", "content-security-policy",
				"This endpoint returns HTML; without CSP, an XSS elsewhere on the app is not contained. No XSS was demonstrated here — this is a defense-in-depth gap.")
		} else {
			f := mkHardening(url, "Missing Content-Security-Policy on non-HTML endpoint", "content-security-policy", ct)
			out = append(out, f)
		}
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		if isHTML {
			add("LOW", "Missing clickjacking protection (HTML response)", "x-frame-options",
				"This endpoint returns HTML and could be framed; clickjacking impact depends on the presence of a sensitive state-changing UI action, which was not verified.")
		} else {
			f := mkHardening(url, "Missing X-Frame-Options on non-HTML endpoint", "x-frame-options", ct)
			out = append(out, f)
		}
	}
	if h.Get("X-Content-Type-Options") == "" {
		add("LOW", "Missing X-Content-Type-Options: nosniff", "x-content-type-options",
			"MIME-sniffing protection absent; exploitable only if the app serves user-controlled content with a wrong/absent content type.")
	}

	// CORS: ACAO:* is only a vulnerability with credentials + sensitive readable data.
	if aco := h.Get("Access-Control-Allow-Origin"); aco == "*" {
		if strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true") {
			add("MEDIUM", "Permissive CORS with credentials (ACAO:* + ACAC:true)", "access-control-allow-origin",
				"Wildcard origin combined with credentialed requests can let any site read authenticated responses. Confirm the endpoint returns sensitive data to a logged-in user.")
			out[len(out)-1].Validation = "config-inferred"
		} else {
			f := mkHardening(url, "Permissive CORS header (ACAO:* without credentials)", "access-control-allow-origin", ct)
			f.ImpactText = "ACAO:* without Allow-Credentials does not expose authenticated data; not a CORS vulnerability by itself. Hardening deviation."
			out = append(out, f)
		}
	}
	return out
}

// mkHardening builds an INFORMATIONAL, not-applicable "hardening deviation" finding —
// used when a control is absent but no attack primitive exists for this asset.
func mkHardening(url, title, header, ct string) Finding {
	return Finding{
		Title:        title,
		Host:         url,
		Severity:     "INFORMATIONAL",
		Status:       "open",
		Confidence:   "Confirmed",
		Validation:   "passive",
		ImpactText:   "No direct exploitability demonstrated (endpoint content-type: " + dash(ct) + "). Hardening deviation, not a vulnerability for this asset.",
		EvidenceCmd:  fmt.Sprintf("curl -skI %s | grep -i %q || echo MISSING", shellQuote(url), header),
		ExpectedOpen: "MISSING",
		ProbeKind:    "header-missing", ProbeURL: url, ProbeArg: header,
	}
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
				Confidence:   "Confirmed",           // protocol was actually negotiated
				Validation:   "behavior-confirmed",  // we completed a handshake at this version
				ImpactText:   "The server completed a " + name + " handshake. On a hostile network this enables downgrade/interception of sessions to this host. Deprecated by RFC 8996.",
				ObservedEvidence: "Completed a " + name + " TLS handshake to " + host + ":443 (connection accepted at this protocol version).",
				EvidenceCmd:  fmt.Sprintf("echo | openssl s_client -connect %s:443 -%s 2>/dev/null | grep -q 'Cipher is' && echo ACCEPTED", shellQuote(host), strings.ToLower(strings.ReplaceAll(name, " ", ""))),
				ExpectedOpen: "ACCEPTED",
				ProbeKind:    "tls-weak", ProbeURL: url, ProbeArg: strings.TrimPrefix(name, "TLS "),
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
		buf := make([]byte, 32768)
		nread, _ := readFull(resp.Body, buf)
		resp.Body.Close()
		body := string(buf[:nread])
		hasSig := strings.Contains(body, sig.signature)
		if code != 200 || (!hasSig && baseCode == 200) {
			continue // not exposed, or catch-all 200
		}
		f := Finding{
			ID:           fmt.Sprintf("EXP-%02d", i),
			Title:        sig.title,
			Host:         base + p,
			Status:       "open",
			EvidenceCmd:  fmt.Sprintf("curl -sk %s | head", shellQuote(base+p)),
			ExpectedOpen: "200",
			ProbeKind:    probeKindFor(hasSig), ProbeURL: base + p, ProbeArg: sig.signature,
		}
		if hasSig {
			f.Confidence, f.Validation = "Confirmed", "behavior-confirmed"
		} else {
			f.Confidence, f.Validation = "Medium", "config-inferred"
		}
		// Deep-inspect Prometheus metrics: severity follows what is actually leaked.
		if p == "/metrics" && hasSig {
			leaked := inspectMetrics(body)
			f.ObservedEvidence = "Sampled response classes: " + orNone(strings.Join(leaked, ", ")) + "\n" + redactedSample(body, 5)
			hasSecretPattern := false
			for _, l := range leaked {
				if strings.Contains(l, "credential-like") {
					hasSecretPattern = true
				}
			}
			switch {
			case hasSecretPattern:
				f.Severity = "HIGH"
				f.ImpactText = "The sampled response matched credential-like label patterns (see Observed Evidence). If confirmed to be real secrets, this is a direct credential exposure. Pattern-based — manual validation required to confirm the matched labels are genuine secrets, not benign metric names."
			case len(leaked) > 0:
				f.Severity = "MEDIUM"
				f.ImpactText = "Unauthenticated Prometheus metrics disclose the following classes in the sampled response: " + strings.Join(leaked, ", ") + ". This aids internal reconnaissance (topology/version intelligence). No credentials were observed."
			default:
				f.Severity = "LOW"
				f.Title = "Prometheus metrics exposed unauthenticated (generic runtime metrics only)"
				f.ImpactText = "Endpoint returns generic process/runtime metrics; no internal hostnames, versions, credentials, or topology were observed in the sampled response. Hardening/monitoring concern, not a direct compromise path."
			}
		} else {
			// non-metrics exposure: HIGH when a strong signature matched, else MEDIUM
			if hasSig {
				f.Severity = "HIGH"
			} else {
				f.Severity = "MEDIUM"
			}
			f.ImpactText = "Endpoint " + base + p + " is reachable unauthenticated and returned content matching a known-sensitive signature; review the exact content for internal detail before acting."
			f.ObservedEvidence = "GET " + base + p + " → HTTP " + fmt.Sprint(code) + "; response matched signature " + shellQuote(sig.signature) + ".\n" + redactedSample(body, 4)
		}
		out = append(out, f)
	}
	return out
}

// readFull reads up to len(buf) bytes.
func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
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

// inspectMetrics classifies what a Prometheus /metrics body actually discloses.
// Returns human-readable categories of sensitive data observed (empty = generic).
func inspectMetrics(body string) []string {
	var found []string
	add := func(label string, cond bool) {
		if cond {
			found = append(found, label)
		}
	}
	l := strings.ToLower(body)
	add("internal hostnames", reInternalHost.MatchString(body))
	add("kubernetes namespace/pod/service names", strings.Contains(l, "namespace=") || strings.Contains(l, "pod=") || strings.Contains(l, "kubernetes_") || strings.Contains(l, "kube_"))
	add("private/internal IP addresses", rePrivateIP.MatchString(body))
	add("software version/build info", strings.Contains(l, "build_info") || strings.Contains(l, "_version{") || strings.Contains(l, "version_info"))
	add("database/queue/backend names", strings.Contains(l, "database=") || strings.Contains(l, "db_name") || strings.Contains(l, "queue=") || strings.Contains(l, "upstream="))
	add("credential-like label patterns (pattern match — validate, not confirmed secrets)", reSecretish.MatchString(body))
	add("cloud region/bucket identifiers", strings.Contains(l, "region=") || strings.Contains(l, "bucket=") || strings.Contains(l, "s3_"))
	return found
}

var (
	reInternalHost = regexp.MustCompile(`(?i)[a-z0-9_.-]+\.(internal|local|svc|cluster\.local|intranet|corp)\b`)
	rePrivateIP    = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`)
	reSecretish    = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|token|bearer|authorization)\s*[=:"']`)
)

func probeKindFor(hasSig bool) string {
	if hasSig {
		return "body-contains"
	}
	return "status"
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
			ProbeKind:    "manual",
		}
		classify(&f)
		out = append(out, f)
	}
	return out
}

// orNone returns "(none)" for an empty string.
func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

// redactedSample returns up to n non-empty lines of a response body, with
// credential-like values redacted, prefixed as observed evidence.
func redactedSample(body string, n int) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = reSecretish.ReplaceAllString(line, "$1=[REDACTED] ")
		if len(line) > 160 {
			line = line[:160] + "…"
		}
		out = append(out, "  "+line)
		if len(out) >= n {
			break
		}
	}
	if len(out) == 0 {
		return "  (no sample lines)"
	}
	return "sample:\n" + strings.Join(out, "\n")
}
