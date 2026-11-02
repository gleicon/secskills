package main

import (
	"fmt"
	"strings"
)

// findingType is the specific condition (not the OWASP class) — it drives
// remediation and business-risk text so a TLS finding never shows crypto-storage
// advice. Derived from the probe + title.
func findingType(f *Finding) string {
	t := strings.ToLower(f.Title)
	switch {
	case f.ProbeKind == "tls-weak" || strings.Contains(t, "tls 1.0") || strings.Contains(t, "tls 1.1") || strings.Contains(t, "weak tls") || strings.Contains(t, "3des") || strings.Contains(t, "cipher"):
		return "tls-deprecated"
	case strings.Contains(t, "hsts"):
		return "hsts-missing"
	case strings.Contains(t, "content-security-policy") || strings.Contains(t, "csp"):
		return "csp-missing"
	case strings.Contains(t, "x-content-type") || strings.Contains(t, "nosniff"):
		return "nosniff-missing"
	case strings.Contains(t, "clickjack") || strings.Contains(t, "x-frame"):
		return "xfo-missing"
	case strings.Contains(t, "cors"):
		return "cors"
	case strings.Contains(t, "prometheus") || strings.Contains(t, "metrics"):
		return "metrics-exposed"
	case strings.Contains(t, "actuator") || strings.Contains(t, "pprof") || strings.Contains(t, ".git") || strings.Contains(t, "server-status") || strings.Contains(t, "exposed path"):
		return "exposure-path"
	case strings.Contains(t, "potentially vulnerable") || strings.Contains(t, "outdated component"):
		return "component-lead"
	case strings.Contains(t, "prompt-injection"):
		return "prompt-injection"
	case strings.Contains(t, "system prompt"):
		return "llm-sysleak"
	case strings.Contains(t, "canary"):
		return "llm-canary"
	case strings.Contains(t, "oracle drift"):
		return "llm-drift"
	case strings.Contains(t, "chatbot performs"):
		// distinct condition from parameter SSRF: both carry http.ssrf@1 and
		// ProbeKind manual, so without this they share one observation key.
		return "llm-chatbot-fetch"
	}
	return ""
}

// remediationByType returns condition-specific remediation. Falls back to the
// cheat-sheet content (kbRemediation) when the type is unknown.
func remediationByType(f *Finding) string {
	// Detector-keyed remediation first — prevents cross-family contamination
	// (e.g. password-hashing advice attaching to an authorization finding).
	switch detectorOf(f) {
	case "http.authz-boundary@1":
		return "" // negative evidence: a control that held needs no remediation
	case "edge.origin-exposure@1":
		return "- Restrict the origin to accept traffic only from the CDN/WAF (IP allow-list of edge ranges, authenticated origin pulls, or mTLS).\n- Rotate the origin IP and ensure it is not discoverable via historical DNS, certificate transparency, or favicon/JARM pivots.\n- Terminate direct-to-origin TLS with a client-cert requirement so only the edge can connect."
	case "edge.header-acl-bypass@1":
		return "- Strip inbound `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Forwarded-Host`, and `X-Original-URL` at the edge; never trust client-supplied values for authorization.\n- Make access decisions on the authenticated identity, not on IP/host headers.\n- Normalize header parsing so the edge and origin agree (no case/whitespace/duplicate differentials)."
	case "http.open-redirect@1":
		return "- Validate redirect targets against an allow-list of known paths/hosts; reject absolute or protocol-relative URLs.\n- Prefer server-side mapping tokens over user-supplied URLs in redirect parameters."
	case "ssti.arithmetic@1":
		return "- Do not pass user input into template rendering; use logic-less templates or strict sandboxing.\n- Context-encode output; upgrade the template engine and disable dangerous features.\n- Manually confirm the injection and assess RCE reachability."
	case "http.ssrf@1":
		return "- Enforce an egress allow-list; block requests to internal/link-local ranges and cloud metadata (169.254.169.254).\n- Resolve and pin destinations server-side; reject user-controlled URLs/schemes.\n- Require authentication on internal services (defense in depth)."
	case "http.rate-limit-absent@1":
		return "- Add per-IP / per-identity rate-limiting and abuse controls on unauthenticated endpoints (WAF rule, gateway policy, or app middleware).\n- Return `429` with `Retry-After` and monitor for abuse."
	case "llm.canary-reflection@1":
		return "- Treat the LLM path as untrusted: rotate every real credential that crossed it; never send production secrets through a third-party router.\n- Add a fail-closed tool policy gate (allow-listed installer domains AND package names) and response-side anomaly screening on tool-call args.\n- Keep an append-only log of executed tool calls and diff it against model-side logs."
	case "llm.response-drift@1":
		return "- Pin the model version and set temperature 0 for a reference run; persistent drift indicates trigger-gated rewriting upstream.\n- Collapse relay chains to the fewest trusted hops and re-probe; inventory every token flow behind the endpoint."
	case "llm.system-prompt-leak@1":
		return "- Move secrets, policy, and tool capability details out of the system prompt; nothing in the prompt is confidential against this attack.\n- Enforce authorization and safety server-side (capability gates on tool execution), never by instruction text alone."
	case "identity.oidc-surface@1":
		return "- Confirm the OIDC discovery exposure is intended; review authorization/token endpoints, redirect-URI validation, PKCE enforcement, and token audience/lifetime in an authorized identity-focused pass."
	case "api.schema-exposure@1", "api.verbose-error@1":
		return "- Restrict API schema/introspection to authenticated internal use in production; disable GraphQL introspection where not intended.\n- Return generic errors; never leak stack traces, framework versions, or file paths."
	case "tech.service-fingerprint@1":
		return "" // fingerprint context only; the service-specific pack carries remediation
	case "dns.dnssec-unknown@1":
		return "" // explicit non-evaluation, not a finding
	}
	switch findingType(f) {
	case "tls-deprecated":
		return "- Disable TLS 1.0 and TLS 1.1; require TLS 1.2+ (prefer TLS 1.3).\n" +
			"- Remove obsolete cipher suites (3DES, RC4, EXPORT, NULL, static-DH).\n" +
			"- Enforce the policy centrally at the load balancer / ingress / CDN.\n" +
			"- Validate client compatibility, then retest protocol negotiation."
	case "hsts-missing":
		return "- Emit `Strict-Transport-Security` on all HTTPS responses.\n" +
			"- Set an appropriate `max-age` (ramp up; e.g. start 300, raise to 31536000).\n" +
			"- Evaluate `includeSubDomains`; consider `preload` only after a domain-wide compatibility review.\n" +
			"- Enforce HTTP→HTTPS redirects; verify first-load exposure."
	case "csp-missing":
		return "- Add a restrictive `Content-Security-Policy` (nonce/hash for inline; `object-src 'none'`, `base-uri 'none'`).\n" +
			"- Only material for HTML responses; scope the policy to rendered pages.\n" +
			"- Roll out in `Content-Security-Policy-Report-Only` first, then enforce."
	case "nosniff-missing":
		return "- Send `X-Content-Type-Options: nosniff`.\n" +
			"- Ensure responses set a correct, explicit `Content-Type`.\n" +
			"- Only exploitable where the app serves user-controlled content with a wrong/absent type."
	case "xfo-missing":
		return "- Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and/or CSP `frame-ancestors 'none'`.\n" +
			"- Only material for HTML with sensitive state-changing UI actions."
	case "cors":
		return "- Do not reflect arbitrary `Origin` with `Access-Control-Allow-Credentials: true`.\n" +
			"- Allow-list exact trusted origins; never combine `ACAO: *` with credentials or sensitive data."
	case "metrics-exposed":
		return "- Require authentication / network restriction (VPN, allow-list, mTLS) on `/metrics`.\n" +
			"- Remove sensitive labels; scrub credentials/tokens from exported series.\n" +
			"- Front operational endpoints with an authenticating gateway."
	case "exposure-path":
		return "- Restrict or remove the exposed endpoint; require authentication.\n" +
			"- If it is a debug/config/VCS artifact, disable it in production and rotate any exposed secrets."
	case "component-lead":
		return "- Confirm the exact running build (this is banner-inferred), then upgrade to a fixed release if the deployment is genuinely affected.\n" +
			"- Note: hiding the version banner reduces fingerprinting only — it is NOT remediation.\n" +
			"- Where possible, run a CVE-specific applicability probe before scheduling emergency patching."
	case "prompt-injection":
		return "- Treat all target-derived content as data; strip/neutralize before it reaches an LLM.\n" +
			"- Remove the adversarial instruction text from the responding endpoint."
	}
	if r := kbRemediation(f.KBClass); r != "" {
		return r
	}
	return remediationFor(f.KBClass)
}

// businessRiskFor returns condition- and confidence-aware business risk. When no
// impact was demonstrated it says so, instead of inventing dramatic prose.
func businessRiskFor(f *Finding) string {
	if isInconclusive(f) {
		return "Potential risk. If the endpoint is reachable without authentication and returns sensitive operational content, it could disclose internal information — but exposure was **not confirmed** during this run (validation blocked/unreachable). Re-test from an unblocked vantage point to confirm or clear."
	}
	if f.Severity == "INFORMATIONAL" {
		return "No material business impact demonstrated. Defense-in-depth / hardening deviation."
	}
	switch findingType(f) {
	case "nosniff-missing":
		return "Limited standalone risk. If the app serves attacker-controlled content with an incorrect MIME type, browser content-sniffing can increase exploitability."
	case "csp-missing":
		return "Limited standalone risk. No XSS was demonstrated; without CSP, an XSS elsewhere in the app would not be contained."
	case "xfo-missing":
		return "Limited standalone risk. Impact depends on a framable page with a sensitive state-changing action, which was not verified."
	case "hsts-missing":
		return "Low standalone risk. A network attacker could strip TLS on a first, pre-redirect request; defense-in-depth for the domain."
	case "tls-deprecated":
		return "On a hostile network, an on-path attacker with a suitable client/cipher/downgrade condition could intercept sessions to this host. Requires network position — not remotely exploitable by itself."
	case "cors":
		return "Depends on credentials + sensitive readable data. Without `Allow-Credentials`, no authenticated data is exposed."
	case "metrics-exposed":
		return "Unauthenticated operational data aids reconnaissance; business impact depends on exactly what is exposed (see Observed Evidence)."
	case "component-lead":
		return "Unconfirmed. If the running build is genuinely the affected version and the vulnerable feature is enabled, a documented exploit could apply — this is a lead, not a demonstrated exposure."
	}
	return businessRisk(f.KBClass, f.Severity)
}

// severityFromScore maps a CVSS base score to the qualitative band (FIRST.org).
func severityFromScore(score float64) string {
	switch {
	case score == 0:
		return "INFORMATIONAL"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// severityJustification reconciles the computed CVSS score with the assessment
// severity, making any deliberate adjustment explicit (no LOW-vs-5.3 contradiction).
func severityJustification(f *Finding) string {
	if cvssNotApplicable(f) {
		if strings.EqualFold(f.Severity, "INFORMATIONAL") {
			return "Informational / negative evidence — CVSS is N/A (CVSS scores a vulnerability, not a control that held or a context observation)."
		}
	}
	_, score := cvssVector(f)
	band := severityFromScore(score)
	if strings.EqualFold(band, f.Severity) {
		return fmt.Sprintf("CVSS base %.1f (%s band), consistent with the assessment severity.", score, band)
	}
	reason := "no demonstrated exploit prerequisite; defense-in-depth only"
	switch findingType(f) {
	case "component-lead":
		reason = "version-inferred lead; exploitability not established, so downgraded from the nominal band"
	case "cors":
		reason = "no credentialed sensitive-data exposure, so not treated as a vulnerability"
	case "tls-deprecated":
		reason = "requires a network position and a vulnerable client/cipher/downgrade condition"
	}
	return fmt.Sprintf("CVSS base score %.1f (%s band); **assessment severity %s** — %s.", score, band, f.Severity, reason)
}

// detectorIDFor names the detector that produced a finding (audit identity).
func detectorIDFor(f *Finding) string {
	if f.DetectorID != "" {
		return f.DetectorID
	}
	switch findingType(f) {
	case "tls-deprecated":
		return "tls.deprecated-protocol@1"
	case "hsts-missing":
		return "http.header.hsts-missing@1"
	case "csp-missing":
		return "http.header.csp-missing@1"
	case "nosniff-missing":
		return "http.header.nosniff-missing@1"
	case "xfo-missing":
		return "http.header.xfo-missing@1"
	case "cors":
		return "http.cors@1"
	case "llm-canary":
		return "llm.canary-reflection@1"
	case "llm-drift":
		return "llm.response-drift@1"
	case "llm-sysleak":
		return "llm.system-prompt-leak@1"
	case "metrics-exposed":
		return "http.prometheus.public-metrics@1"
	case "exposure-path":
		return "http.exposure-path@1"
	case "component-lead":
		return "component.banner-osv-correlation@1"
	case "prompt-injection":
		return "content.prompt-injection@1"
	}
	if strings.HasPrefix(strings.ToLower(f.Title), "nuclei:") {
		return "nuclei@1"
	}
	return "generic@1"
}
