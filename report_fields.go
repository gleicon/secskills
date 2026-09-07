package main

import (
	"fmt"
	"strings"
)

// slaFor returns the remediation SLA per severity (playbook §05).
func slaFor(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "7 days"
	case "HIGH":
		return "30 days"
	case "MEDIUM":
		return "90 days"
	case "LOW":
		return "next release"
	default:
		return "backlog"
	}
}

// businessRisk is the one-sentence, non-engineer business-impact lead required for
// every finding (playbook §03 field 5, §05 two-audience rule).
func businessRisk(kbClass, sev string) string {
	switch kbClass {
	case "components-supply-chain":
		return "A publicly documented exploit for this component could let an attacker take over the host without insider access."
	case "crypto-secrets":
		return "Traffic to this service can be intercepted or downgraded on a hostile network, exposing customer sessions and data."
	case "config-exposure":
		return "Operational internals are exposed to anyone on the internet, aiding a targeted attack and potentially leaking secrets."
	case "access-control":
		return "A user could reach data or actions that are not theirs — a direct path to tenant data exposure."
	case "auth-session":
		return "Accounts on this service are more easily taken over, risking unauthorized access to customer or corporate data."
	case "injection":
		return "An attacker could run unintended queries or code, leading to data theft or service compromise."
	case "ssrf-xxe":
		return "The server can be tricked into reaching internal systems and cloud credentials, enabling deeper compromise."
	case "logging-monitoring":
		return "Attacks against this service may go undetected, extending the window of a breach."
	case "llm-agents":
		return "The AI feature can be manipulated to leak data or misuse its tools on a user's behalf."
	case "mobile":
		return "Credentials or customer data on the device or in transit are at risk of theft."
	default:
		return "This weakness increases the likelihood or impact of a successful attack on the service."
	}
}

// severityRationale explains a rating using the playbook's gut-check adjustments,
// so the number is defensible without a CVSS calculator.
func severityRationale(f *Finding) string {
	var factors []string
	host := strings.ToLower(f.Host)
	remote := strings.HasPrefix(host, "http")
	if remote {
		factors = append(factors, "remotely reachable")
	}
	if strings.Contains(strings.ToLower(f.Title), "unauth") || f.KBClass == "config-exposure" || f.KBClass == "components-supply-chain" {
		factors = append(factors, "no authentication required")
	}
	if f.KBClass == "components-supply-chain" || strings.Contains(strings.ToLower(f.Title), "rce") {
		factors = append(factors, "can lead to host compromise")
	}
	if len(factors) == 0 {
		return fmt.Sprintf("Rated %s per CVSS v3.1 band %s.", f.Severity, cvssBand(f.Severity))
	}
	return fmt.Sprintf("Rated %s (CVSS band %s): %s.", f.Severity, cvssBand(f.Severity), strings.Join(factors, ", "))
}

// attackNarrative synthesizes a chronological chaining story from the findings —
// the playbook's signature §07 section, generically (no target-specific hardcoding).
func attackNarrative(findings []Finding, live []LiveHost, subs []string) string {
	classes := map[string]int{}
	var highs []string
	for _, f := range findings {
		classes[f.KBClass]++
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			highs = append(highs, f.Title+" ("+f.Host+")")
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "During reconnaissance, %d subdomains were enumerated and %d live services identified. ", len(subs), len(live))
	// count auth-gated as a control
	gated := 0
	for _, l := range live {
		if l.Status == 401 || l.Status == 403 {
			gated++
		}
	}
	if gated > 0 {
		fmt.Fprintf(&b, "Sensitive services (%d) enforced authentication and resisted unauthenticated access. ", gated)
	}
	if len(highs) == 0 {
		b.WriteString("No individual finding reached high severity; the exposure is an accumulation of hardening gaps rather than a single break. ")
	} else {
		fmt.Fprintf(&b, "The highest-impact issues were: %s. ", strings.Join(capList(highs, 5), "; "))
	}
	// chaining logic
	var chain []string
	if classes["config-exposure"] > 0 && classes["logging-monitoring"] >= 0 {
		chain = append(chain, "exposed operational endpoints (metrics/config) hand an attacker internal topology and version data")
	}
	if classes["components-supply-chain"] > 0 {
		chain = append(chain, "that version data maps directly to public CVEs on outdated components, giving a concrete exploit path")
	}
	if classes["crypto-secrets"] > 0 {
		chain = append(chain, "weak transport (TLS 1.0/1.1, missing HSTS) lets an on-path attacker intercept sessions to those services")
	}
	if len(chain) >= 2 {
		fmt.Fprintf(&b, "Chained, these compound: %s. Individually low-to-medium, together they shorten the path from external attacker to a foothold. ", strings.Join(chain, "; then "))
	}
	b.WriteString("A credentialed follow-up would extend this narrative into authenticated authorization and business-logic testing.")
	return b.String()
}

// appendices renders tools-used + the cleanup log (playbook §08).
func appendices(wd string, authStatus string) string {
	var b strings.Builder
	b.WriteString("### Tools used\n\n")
	tools := []string{"subfinder", "dnsx", "httpx", "sslscan", "nuclei", "osv-scanner (OSV API)", "shodan", "ast-grep", "secskills native check engine"}
	present := []string{}
	for _, t := range tools {
		name := strings.Fields(t)[0]
		if has(name) || name == "secskills" || name == "osv-scanner" {
			present = append(present, t)
		}
	}
	b.WriteString("- " + strings.Join(present, "\n- ") + "\n\n")
	b.WriteString("### Cleanup log (test-artifact attestation)\n\n")
	b.WriteString("This was a **non-destructive** assessment. secskills sends only GET/HEAD/OPTIONS and read-only requests; it does **not** create accounts, upload files, plant web shells, or write to the target. Therefore:\n\n")
	b.WriteString("- Test accounts created: **none**\n")
	b.WriteString("- Web shells / payloads planted: **none**\n")
	b.WriteString("- Data written to target: **none**\n")
	if authStatus == "provided" {
		b.WriteString("- Credentials used: operator-supplied token/cookie (value redacted; revoke if it was issued for this test)\n")
	} else {
		b.WriteString("- Credentials used: **none** (unauthenticated assessment)\n")
	}
	b.WriteString("\nNo cleanup actions are required on the target.")
	return b.String()
}

func capList(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
