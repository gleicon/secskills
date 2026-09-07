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
		return fmt.Sprintf("Rated %s; CVSS v3.1 base %s.", f.Severity, cvssScoreStr(f))
	}
	return fmt.Sprintf("Rated %s (CVSS v3.1 base %s): %s.", f.Severity, cvssScoreStr(f), strings.Join(factors, ", "))
}

// attackNarrative is graph-derived: it references only conditions actually present
// in the findings and preserves the confidence boundary between confirmed
// disclosure, inference, and unvalidated hypothesis (no compressed overclaims).
func attackNarrative(findings []Finding, live []LiveHost, subs []string) string {
	// presence of specific, evidence-graded conditions
	var metricsSensitive, metricsGeneric, componentLead, tlsWeak, exposurePath bool
	var highs []string
	for i := range findings {
		f := &findings[i]
		switch findingType(f) {
		case "metrics-exposed":
			if f.Severity == "HIGH" || f.Severity == "MEDIUM" {
				metricsSensitive = true
			} else {
				metricsGeneric = true
			}
		case "component-lead":
			componentLead = true
		case "tls-deprecated":
			tlsWeak = true
		case "exposure-path":
			exposurePath = true
		}
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			highs = append(highs, f.Title+" ("+f.Host+")")
		}
	}
	gated := 0
	for _, l := range live {
		if l.Status == 401 || l.Status == 403 {
			gated++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "During reconnaissance, %d subdomains were enumerated and %d live services identified. ", len(subs), len(live))
	if gated > 0 {
		fmt.Fprintf(&b, "%d sensitive services enforced authentication (HTTP 401/403) and resisted unauthenticated access. ", gated)
	}
	if len(highs) > 0 {
		fmt.Fprintf(&b, "Highest-impact observations: %s. ", strings.Join(capList(highs, 5), "; "))
	} else {
		b.WriteString("No individual observation reached high severity; the posture is an accumulation of hardening gaps, not a single break. ")
	}

	// chain — each edge included only if the source condition is present, with its
	// confidence stated (confirmed → inferred → unvalidated hypothesis).
	var chain []string
	if metricsSensitive || exposurePath {
		chain = append(chain, "**[confirmed disclosure]** an unauthenticated operational endpoint returned internal detail (see the finding's Observed Evidence) → improves target selection and topology/version intelligence")
	} else if metricsGeneric {
		chain = append(chain, "**[confirmed, low value]** an unauthenticated metrics endpoint returned only generic runtime metrics → no internal detail to leverage")
	}
	if componentLead {
		chain = append(chain, "**[unvalidated hypothesis]** banner-inferred component versions correlate with public CVEs → a *potential* component exploit, NOT a demonstrated one (exploitability unproven; distro backports may already patch it)")
	}
	if tlsWeak {
		chain = append(chain, "**[requires network position]** deprecated TLS 1.0/1.1 acceptance → interception is possible only for an on-path attacker with a vulnerable client/cipher/downgrade condition, not remotely by itself")
	}
	if len(chain) > 0 {
		b.WriteString("Chaining the observed conditions (confidence preserved):\n\n")
		for _, c := range chain {
			b.WriteString("- " + c + "\n")
		}
		b.WriteString("\nNo edge in this chain reaches a demonstrated compromise: the confirmed links are information-disclosure and configuration, and the exploit link is an unvalidated hypothesis. ")
	}
	b.WriteString("A credentialed follow-up would be required to extend this into authenticated authorization and business-logic testing.")
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
