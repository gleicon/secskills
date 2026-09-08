package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Adversarial-readonly modules: request-variant authorization-bypass testing and
// harmless exploit primitives. All are GET-only, bounded, and stop at a defined
// proof boundary (prove the primitive, not maximum impact).

// bypassClasses are read-only authorization-bypass variants attempted against a
// protected (401/403) endpoint. Each is a defined class so a *pass* can be stated
// as "resisted N bypass classes" rather than a bare 403.
var bypassClasses = []struct {
	name    string
	mutate  func(req *http.Request, u string) *http.Request
}{
	{"X-Forwarded-For spoof", func(r *http.Request, u string) *http.Request { r.Header.Set("X-Forwarded-For", "127.0.0.1"); return r }},
	{"X-Original-URL override", func(r *http.Request, u string) *http.Request { r.Header.Set("X-Original-URL", "/"); return r }},
	{"X-Rewrite-URL override", func(r *http.Request, u string) *http.Request { r.Header.Set("X-Rewrite-URL", "/"); return r }},
	{"X-Forwarded-Host spoof", func(r *http.Request, u string) *http.Request { r.Header.Set("X-Forwarded-Host", "localhost"); return r }},
	{"trailing-slash normalization", nil},
	{"trailing-dot normalization", nil},
	{"case variation", nil},
	{"double-encoded separator", nil},
}

// bypassProbe attempts read-only bypass variants against a protected endpoint.
// Returns a finding ONLY if a variant unexpectedly succeeds (200); otherwise it
// records the count of resisted classes as negative evidence on the endpoint.
func bypassProbe(wd, protectedURL string, baseCode int) *Finding {
	if baseCode != 401 && baseCode != 403 {
		return nil
	}
	resisted, bypassed := 0, ""
	for _, bc := range bypassClasses {
		vurl := protectedURL
		switch bc.name {
		case "trailing-slash normalization":
			vurl = strings.TrimRight(protectedURL, "/") + "/"
		case "trailing-dot normalization":
			vurl = protectedURL + "."
		case "case variation":
			vurl = caseFlipPath(protectedURL)
		case "double-encoded separator":
			vurl = strings.Replace(protectedURL, "/", "/%2e/", 1)
		}
		if err := ssrfSafeURL(vurl); err != nil {
			continue
		}
		req, err := http.NewRequest("GET", vurl, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		if bc.mutate != nil {
			req = bc.mutate(req, vurl)
		}
		resp, err := nonDestructiveClient().Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			bypassed = bc.name
			break
		}
		resisted++
	}
	if bypassed != "" {
		ev := captureEvidence(wd, "http.authz-bypass@1", protectedURL, "http-response", "text/plain", "GET "+protectedURL+" ("+bypassed+")", "none",
			[]byte("bypass class '"+bypassed+"' returned HTTP 200 on a "+itoa(baseCode)+"-protected endpoint"))
		return &Finding{
			Title: "Authorization bypass via " + bypassed, Host: protectedURL, Severity: "HIGH", Status: "open",
			Confidence: "Confirmed", Validation: "exploited",
			ObservedEvidence: fmt.Sprintf("Endpoint returned HTTP %d normally; the %q variant returned HTTP 200, bypassing the control.", baseCode, bypassed),
			ImpactText:  "A defined authorization-bypass variant reached protected content. This is a validated access-control weakness.",
			EvidenceCmd: "curl -sk " + shellQuote(protectedURL) + " with variant " + shellQuote(bypassed),
			ProbeKind:   "status", ProbeURL: protectedURL, EvidenceRefs: []string{ev}, DetectorID: "http.authz-bypass@1",
			Capabilities: []string{capAuthBoundary},
		}
	}
	// negative evidence: resisted N classes (records that we actively tried)
	ev := captureEvidence(wd, "http.authz-boundary@1", protectedURL, "detector-parse", "text/plain", "GET "+protectedURL+" (bypass matrix)", "none",
		[]byte(fmt.Sprintf("resisted %d/%d defined bypass classes", resisted, len(bypassClasses))))
	return &Finding{
		Title: fmt.Sprintf("Authorization boundary resisted %d bypass classes", resisted), Host: protectedURL, Severity: "INFORMATIONAL", Status: "open",
		Confidence: "Confirmed", Validation: "behavior-confirmed",
		ObservedEvidence: fmt.Sprintf("Protected endpoint (HTTP %d) resisted %d/%d defined read-only bypass classes (forwarded headers, URL-override headers, path normalization, case, encoding).", baseCode, resisted, len(bypassClasses)),
		ImpactText:  "Negative evidence: the authorization boundary held against the tested bypass variants. Not a weakness.",
		ProbeKind:   "status", ProbeURL: protectedURL, EvidenceRefs: []string{ev}, DetectorID: "http.authz-boundary@1",
		Capabilities: []string{capAuthBoundary},
	}
}

func caseFlipPath(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return u
	}
	host := rest[:slash]
	path := rest[slash:]
	return u[:i+3] + host + strings.ToUpper(path[:1]) + path[1:]
}

// openRedirectProbe tests common redirect params for an off-site redirect to a
// canary. GET-only; confirms via the Location header, no victim involved.
func openRedirectProbe(wd, base string) *Finding {
	canary := "https://secskills-canary.example"
	for _, param := range []string{"url", "redirect", "next", "return", "returnUrl", "dest", "destination", "continue", "r"} {
		u := strings.TrimRight(base, "/") + "/?" + param + "=" + url.QueryEscape(canary)
		if err := ssrfSafeURL(u); err != nil {
			continue
		}
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", userAgent)
		resp, err := nonDestructiveClient().Do(req)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if strings.HasPrefix(loc, canary) || strings.HasPrefix(loc, "//secskills-canary") {
			ev := captureEvidence(wd, "http.open-redirect@1", base, "http-response", "text/plain", "GET "+u, "none",
				[]byte("Location: "+loc))
			return &Finding{
				Title: "Open redirect via ?" + param, Host: base, Severity: "MEDIUM", Status: "open",
				Confidence: "Confirmed", Validation: "exploited",
				ObservedEvidence: fmt.Sprintf("GET with %s=%s returned Location: %s (redirect to attacker-controlled host).", param, canary, loc),
				ImpactText:  "The endpoint redirects to an attacker-supplied absolute URL, enabling phishing and OAuth-flow abuse. Validate/allow-list redirect targets.",
				EvidenceCmd: "curl -skI " + shellQuote(u) + " | grep -i location", ProbeKind: "status", ProbeURL: u,
				EvidenceRefs: []string{ev}, DetectorID: "http.open-redirect@1", Capabilities: []string{capRedirect},
			}
		}
	}
	return nil
}

// sstiArithmeticProbe sends a harmless arithmetic expression in a reflected param
// and flags SSTI only when the *evaluated* result (49) appears where the literal
// (7*7) does not — a low-false-positive primitive.
func sstiArithmeticProbe(wd, base string) *Finding {
	// Rare operands so a coincidental match is near-impossible: 73819 * 91193 =
	// 6,731,738,867 (a distinctive 10-digit number). We require the evaluated
	// result to appear ONLY when injected (differential vs a control request),
	// the literal expression to be absent, and the template braces to be gone —
	// three independent conditions to keep false positives near zero.
	const a, bb = 73819, 91193
	const product = "6731738867"
	const expr = "73819*91193"
	// control body (no injection) — the number must NOT already be present
	if _, _, ctrl, ok := getWithBody(strings.TrimRight(base, "/")+"/", 32*1024); ok && strings.Contains(ctrl, product) {
		return nil
	}
	for _, tmpl := range []struct{ open, close string }{{"{{", "}}"}, {"${", "}"}, {"#{", "}"}} {
		marker := tmpl.open + expr + tmpl.close
		for _, param := range []string{"q", "search", "name", "s", "query", "input"} {
			u := strings.TrimRight(base, "/") + "/?" + param + "=" + url.QueryEscape(marker)
			code, _, body, ok := getWithBody(u, 32*1024)
			if !ok || code != 200 {
				continue
			}
			if strings.Contains(body, product) && !strings.Contains(body, expr) && !strings.Contains(body, tmpl.open+expr) {
				ev := captureEvidence(wd, "ssti.arithmetic@1", base, "http-response", "text/plain", "GET "+u, "redacted",
					[]byte(fmt.Sprintf("input %s reflected as evaluated result %s (control body did not contain %s)", marker, product, product)))
				return &Finding{
					Title: "Potential server-side template injection (arithmetic evaluated) via ?" + param, Host: base, Severity: "HIGH", Status: "open",
					Confidence: "High", Validation: "behavior-confirmed",
					ObservedEvidence: fmt.Sprintf("Input %s in %s was reflected as the evaluated product %s (= %d*%d); the literal expression was absent and the value did not appear in the un-injected control response — the template expression was executed server-side.", marker, param, product, a, bb),
					ImpactText:  "Server-side template injection can lead to remote code execution depending on the engine. Proof boundary: arithmetic evaluation only — no code execution was attempted.",
					EvidenceCmd: "curl -sk " + shellQuote(u), ProbeKind: "body-contains", ProbeURL: u, ProbeArg: product,
					EvidenceRefs: []string{ev}, DetectorID: "ssti.arithmetic@1", Capabilities: []string{capServerSideFetch},
				}
			}
		}
	}
	return nil
}

// ssrfOASTProbe embeds an OAST canary in common SSRF-prone params; validated only
// by an out-of-band callback (no internal resource is read).
func ssrfOASTProbe(wd, base string, o *OAST) *Finding {
	if !o.available() {
		return nil
	}
	host, id := o.token()
	for _, param := range []string{"url", "uri", "target", "dest", "callback", "webhook", "image", "fetch"} {
		u := strings.TrimRight(base, "/") + "/?" + param + "=" + url.QueryEscape("http://"+host+"/")
		getWithBody(u, 2048) // fire; the target may perform a server-side fetch
	}
	if o.interacted(id) {
		ev := captureEvidence(wd, "http.ssrf@1", base, "detector-parse", "text/plain", "OAST "+host, "none",
			[]byte("out-of-band interaction observed from target to canary "+host))
		return &Finding{
			Title: "Server-side request forgery (OAST-validated)", Host: base, Severity: "HIGH", Status: "open",
			Confidence: "Confirmed", Validation: "exploited",
			ObservedEvidence: "The target performed a server-side fetch to our OAST canary (" + host + "), confirming SSRF. Proof boundary: out-of-band interaction only; no internal resource was read.",
			ImpactText:  "SSRF lets the server make attacker-directed requests (cloud metadata, internal services). Validated out-of-band without reading internal data.",
			ProbeKind: "manual", ProbeURL: base, EvidenceRefs: []string{ev}, DetectorID: "http.ssrf@1", Capabilities: []string{capServerSideFetch},
		}
	}
	return nil
}

// runAdversarial runs the read-only adversarial modules for one base URL.
func runAdversarial(wd, base string, o *OAST) []Finding {
	var out []Finding
	if f := openRedirectProbe(wd, base); f != nil {
		out = append(out, *f)
	}
	if f := sstiArithmeticProbe(wd, base); f != nil {
		out = append(out, *f)
	}
	if f := ssrfOASTProbe(wd, base, o); f != nil {
		out = append(out, *f)
	}
	return out
}
