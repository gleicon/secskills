package finding

import (
	"strings"
)

// Classify maps a finding to the OWASP Top 10 category, CWE, KB cheat-sheet
// class, and reference links — so every finding ties back to the framework,
// our cheatsheets, and (for components) CVE data. Idempotent.
func Classify(f *Finding) {
	t := strings.ToLower(f.Title)
	set := func(owasp, cwe, kb string) { f.OWASP, f.CWE, f.KBClass = owasp, cwe, kb }
	switch {
	case strings.Contains(t, "hsts") || strings.Contains(t, "tls") || strings.Contains(t, "cipher"):
		set("A02:2021 Cryptographic Failures", "CWE-326", "crypto-secrets")
	case strings.Contains(t, "cookie"):
		set("A02:2021 Cryptographic Failures", "CWE-614", "crypto-secrets")
	case strings.Contains(t, "content-security-policy") || strings.Contains(t, "csp"):
		set("A05:2021 Security Misconfiguration", "CWE-1021", "config-exposure")
	case strings.Contains(t, "clickjack") || strings.Contains(t, "x-frame"):
		set("A05:2021 Security Misconfiguration", "CWE-1021", "config-exposure")
	case strings.Contains(t, "cors"):
		set("A05:2021 Security Misconfiguration", "CWE-942", "config-exposure")
	case strings.Contains(t, "nosniff") || strings.Contains(t, "x-content-type"):
		set("A05:2021 Security Misconfiguration", "CWE-693", "config-exposure")
	case strings.Contains(t, "metrics") || strings.Contains(t, "actuator") || strings.Contains(t, "pprof") || strings.Contains(t, "server-status"):
		set("A05:2021 Security Misconfiguration", "CWE-200", "config-exposure")
	case strings.Contains(t, ".git"):
		set("A05:2021 Security Misconfiguration", "CWE-527", "config-exposure")
	case strings.Contains(t, "xss") || strings.Contains(t, "inject") || strings.Contains(t, "sql"):
		set("A03:2021 Injection", "CWE-79", "injection")
	case strings.Contains(t, "ssrf") || strings.Contains(t, "request forgery") || strings.Contains(t, "server-side fetch"):
		set("A10:2021 Server-Side Request Forgery", "CWE-918", "ssrf-xxe")
	case strings.Contains(t, "xxe"):
		set("A05:2021 Security Misconfiguration", "CWE-611", "ssrf-xxe")
	case strings.Contains(t, "cve") || strings.Contains(t, "outdated") || strings.Contains(t, "vulnerable component") || strings.Contains(t, "version"):
		set("A06:2021 Vulnerable and Outdated Components", "CWE-1035", "components-supply-chain")
	case strings.Contains(t, "auth") || strings.Contains(t, "login") || strings.Contains(t, "session") || strings.Contains(t, "password"):
		set("A07:2021 Identification and Authentication Failures", "CWE-287", "auth-session")
	case strings.Contains(t, "access") || strings.Contains(t, "idor") || strings.Contains(t, "admin") || strings.Contains(t, "unauth"):
		set("A01:2021 Broken Access Control", "CWE-284", "access-control")
	case strings.Contains(t, "prompt injection") || strings.Contains(t, "llm") || strings.Contains(t, "agent") || strings.Contains(t, "excessive agency") || strings.Contains(t, "system prompt"):
		set("LLM01:2025 Prompt Injection (OWASP LLM Top 10)", "CWE-77", "llm-agents")
	case strings.Contains(t, "cert pinning") || strings.Contains(t, "cleartext") || strings.Contains(t, "exported component") || strings.Contains(t, "apk") || strings.Contains(t, "ipa") || strings.Contains(t, "mobile"):
		set("M-series (OWASP Mobile Top 10)", "CWE-919", "mobile")
	case strings.Contains(t, "exposed") || strings.Contains(t, "internal tooling") || strings.Contains(t, "metrics") || strings.Contains(t, "registry"):
		set("A05:2021 Security Misconfiguration", "CWE-200", "config-exposure")
	default:
		set("A05:2021 Security Misconfiguration", "CWE-200", "config-exposure")
	}
	f.References = []string{
		"OWASP Top 10: https://owasp.org/Top10/",
		"Cheat sheet: secskills kb " + f.KBClass,
	}
}
