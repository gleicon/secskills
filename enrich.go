package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// classify maps a finding to the OWASP Top 10 category, CWE, KB cheat-sheet
// class, and reference links — so every finding ties back to the framework,
// our cheatsheets, and (for components) CVE data. Idempotent.
func classify(f *Finding) {
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
	case strings.Contains(t, "ssrf"):
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

var verRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]+)/(\d+\.\d+(?:\.\d+)?)`)

// osvEcosystem maps a server product name to an OSV ecosystem+package.
func osvEcosystem(name string) (pkg, eco string) {
	switch strings.ToLower(name) {
	case "nginx":
		return "nginx", "Debian"
	case "apache", "httpd":
		return "apache-httpd", "OSS-Fuzz"
	case "gunicorn":
		return "gunicorn", "PyPI"
	case "openresty":
		return "nginx", "Debian"
	case "lighttpd":
		return "lighttpd", "Debian"
	default:
		return "", ""
	}
}

// osvVuln is the subset of an OSV record we use for precision filtering.
type osvVuln struct {
	ID       string `json:"id"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}


// fixedAfter reports whether the vuln has a fixed version strictly greater than
// ver (i.e. our version is genuinely unpatched for it). If no range data exists,
// returns ok=false so the caller can treat it as low-confidence.
func fixedAfter(v osvVuln, ver string) (unpatched, hasRange bool) {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if fx, ok := e["fixed"]; ok {
					hasRange = true
					if semverLess(ver, fx) {
						unpatched = true
					}
				}
			}
		}
	}
	return
}

// semverLess compares dotted numeric versions (a < b). Non-numeric parts ignored.
func semverLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var ai, bi int
		if i < len(as) {
			fmt.Sscanf(as[i], "%d", &ai)
		}
		if i < len(bs) {
			fmt.Sscanf(bs[i], "%d", &bi)
		}
		if ai != bi {
			return ai < bi
		}
	}
	return false
}

// cveLookup parses a Server header, queries OSV (throttled), and returns a
// component finding (A06). Precision: prefer CVEs that are genuinely unpatched
// for the detected version (fixed range > version) and rank severity by CVSS.
func cveLookup(host, serverHeader string) *Finding {
	m := verRe.FindStringSubmatch(serverHeader)
	if m == nil {
		return nil
	}
	name, ver := m[1], m[2]
	pkg, eco := osvEcosystem(name)
	if pkg == "" {
		return nil
	}
	body, err := httpDo("osv", "POST", "https://api.osv.dev/v1/query",
		fmt.Sprintf(`{"version":%q,"package":{"name":%q,"ecosystem":%q}}`, ver, pkg, eco), 3)
	if err != nil {
		return nil
	}
	var r struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Vulns) == 0 {
		return nil
	}

	// partition: unpatched (fixed>ver) vs range-less (low confidence)
	var unpatched, unranged []string
	maxSev := 0 // 0 none,1 low,2 med,3 high,4 crit
	sevRank := map[string]int{"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for _, v := range r.Vulns {
		up, hasRange := fixedAfter(v, ver)
		if s := sevRank[strings.ToUpper(v.DatabaseSpecific.Severity)]; s > maxSev {
			maxSev = s
		}
		switch {
		case up:
			unpatched = append(unpatched, v.ID)
		case !hasRange:
			unranged = append(unranged, v.ID)
		}
	}
	// If range data existed and none are unpatched, our version is patched → skip.
	if len(unpatched) == 0 && len(unranged) == 0 {
		return nil
	}

	count := len(unpatched)
	ids := unpatched
	if count == 0 { // only range-less matches — lower confidence
		count = len(unranged)
		ids = unranged
	}
	// Version→CVE correlation is a LEAD, not a demonstrated vulnerability: the
	// version is banner-inferred, distro backports keep upstream-looking versions,
	// the OS/build/config/modules are unknown, and exploitability is not proven.
	// Cap at MEDIUM and mark low confidence + manual-validation-required. Only a
	// safe validation of an actual applicable CVE against the host justifies HIGH.
	sev := "MEDIUM"
	if count <= 5 && len(unpatched) == 0 {
		sev = "LOW"
	}
	if len(ids) > 10 {
		ids = ids[:10]
	}
	f := &Finding{
		Title:        fmt.Sprintf("Potentially vulnerable %s version %s — manual validation required (%d CVEs correlate via OSV)", name, ver, count),
		Host:         host,
		Severity:     sev,
		Status:       "open",
		Confidence:   "Low",
		Validation:   "version-inferred",
		ImpactText: fmt.Sprintf("The %s version is inferred from the Server banner. OSV lists %d CVEs for %s/%s in the %s ecosystem, but this does NOT establish that the host runs the vulnerable build/config or that any CVE is remotely exploitable here (backported distro patches keep the same upstream version). Treat as a lead for manual validation, not a confirmed vulnerability.",
			name, count, name, ver, eco),
		EvidenceCmd:  fmt.Sprintf(`curl -s -X POST https://api.osv.dev/v1/query -d '{"version":"%s","package":{"name":"%s","ecosystem":"%s"}}' | jq '[.vulns[]|select(.affected[].ranges[].events[].fixed)]|length'`, ver, pkg, eco),
		ExpectedOpen: "",
		CVEs:         ids,
		ProbeKind:    "manual",
	}
	classify(f)
	// override remediation reference: upgrading is the fix; hiding the banner is NOT.
	f.References = append(f.References, "Remediation: upgrade the component to a fixed release and confirm the running build. Hiding the version banner is fingerprint-reduction, NOT remediation.")
	return f
}

// osvQuery queries OSV for a package@version and returns affecting advisory IDs
// plus the max severity rank (0..4). Used by the runtime planner's CVE-
// applicability probe. Best-effort; empty on any failure.
func osvQuery(pkg, eco, ver string) ([]string, int) {
	body, err := httpDo("osv", "POST", "https://api.osv.dev/v1/query",
		fmt.Sprintf(`{"version":%q,"package":{"name":%q,"ecosystem":%q}}`, ver, pkg, eco), 3)
	if err != nil {
		return nil, 0
	}
	var r struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Vulns) == 0 {
		return nil, 0
	}
	sevRank := map[string]int{"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	var ids []string
	maxSev := 0
	for _, v := range r.Vulns {
		if up, _ := fixedAfter(v, ver); up {
			ids = append(ids, v.ID)
			if s := sevRank[strings.ToUpper(v.DatabaseSpecific.Severity)]; s > maxSev {
				maxSev = s
			}
		}
	}
	return ids, maxSev
}
