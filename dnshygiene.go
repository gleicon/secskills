package main

import (
	"fmt"
	"net"
	"strings"
)

// Item 20 — DNS hygiene detectors (email-auth + delegation posture).
// Run once per apex. Passive DNS lookups only. DNSSEC validation requires a
// DNSSEC-aware resolver (stdlib net does not expose RRSIG/DS); that specific
// check is reported as "not evaluated" rather than guessed.
func dnsHygiene(apex string) []Finding {
	apex = strings.TrimSuffix(strings.ToLower(apex), ".")
	var out []Finding
	mk := func(det, title, sev, obs, impact, arg string) {
		out = append(out, Finding{
			Title: title, Host: apex, Severity: sev, Status: "open",
			Confidence: "Confirmed", Validation: "behavior-confirmed",
			ObservedEvidence: obs, ImpactText: impact,
			EvidenceCmd: "dig +short " + arg + " " + shellQuote(apex),
			ProbeKind:   "manual", ProbeURL: apex, DetectorID: det,
		})
	}
	// SPF
	txts, _ := net.LookupTXT(apex)
	spf := ""
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = t
		}
	}
	if spf == "" {
		mk("dns.spf-missing@1", "No SPF record", "LOW", "No v=spf1 TXT record on "+apex+".",
			"Without SPF, receivers cannot verify authorized senders, easing spoofing of this domain. Publish an SPF record ending in -all or ~all.", "TXT")
	} else if strings.Contains(spf, "+all") {
		mk("dns.spf-weak@1", "Overly permissive SPF (+all)", "MEDIUM", "SPF record: "+safeField(spf),
			"An SPF ending in +all authorizes any sender, defeating the control. Use -all (hard fail) or ~all (soft fail).", "TXT")
	}
	// DMARC
	dmarc, _ := net.LookupTXT("_dmarc." + apex)
	hasDMARC := false
	for _, t := range dmarc {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			hasDMARC = true
			if strings.Contains(strings.ToLower(t), "p=none") {
				mk("dns.dmarc-none@1", "DMARC policy is p=none (monitor only)", "LOW", "DMARC: "+safeField(t),
					"p=none does not enforce; spoofed mail is not rejected/quarantined. Move to p=quarantine then p=reject after monitoring.", "TXT _dmarc.")
			}
		}
	}
	if !hasDMARC {
		mk("dns.dmarc-missing@1", "No DMARC record", "LOW", "No v=DMARC1 TXT record on _dmarc."+apex+".",
			"Without DMARC, SPF/DKIM results are not enforced and spoofing reports are not collected. Publish a DMARC record.", "TXT _dmarc.")
	}
	// Wildcard DNS
	if addrs, err := net.LookupHost("secskills-wildcard-probe-" + randToken() + "." + apex); err == nil && len(addrs) > 0 {
		mk("dns.wildcard@1", "Wildcard DNS resolves arbitrary subdomains", "LOW",
			"A random non-existent subdomain of "+apex+" resolved ("+addrs[0]+"), indicating a wildcard record.",
			"Wildcard DNS can mask dangling records and enable subdomain confusion; confirm it is intentional.", "A '*.")
	}
	// DNSSEC — explicit non-evaluation (honest, not guessed)
	mk("dns.dnssec-unknown@1", "DNSSEC posture not evaluated", "INFORMATIONAL",
		"DNSSEC validation was not performed (requires a DNSSEC-aware resolver; outside the stdlib lookup used here).",
		"Report only — recommend validating DNSSEC (DS/RRSIG presence and chain) in a dedicated DNS assessment.", "DNSKEY")
	return out
}

// nsDelegation reports the NS set for context (delegation posture).
func nsDelegation(apex string) string {
	ns, err := net.LookupNS(strings.TrimSuffix(apex, "."))
	if err != nil || len(ns) == 0 {
		return "NS lookup failed"
	}
	var names []string
	for _, n := range ns {
		names = append(names, strings.TrimSuffix(n.Host, "."))
	}
	return fmt.Sprintf("%d nameservers: %s", len(names), strings.Join(names, ", "))
}
