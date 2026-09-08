package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// reportLint enforces report-generation invariants. Generation fails on any
// violation, so a contradiction (missing confidence, disagreeing screenshot
// counts, unsupported HIGH, malformed tool version, ledger arithmetic) can never
// ship in an audit-evidence report. This is the automated report linter.
func reportLint(target, wd string, findings []Finding) []string {
	var v []string
	live := liveHosts(wd)

	// per-finding invariants
	seenObs := map[string]string{} // observationKey -> control signature
	for i := range findings {
		f := &findings[i]
		tag := fmt.Sprintf("finding %q", f.Title)
		if f.Confidence == "" {
			v = append(v, tag+": missing confidence")
		}
		if f.Validation == "" {
			v = append(v, tag+": missing validation")
		}
		if f.State == "" {
			v = append(v, tag+": missing evidence_state")
		}
		if f.Key == "" {
			v = append(v, tag+": missing observation finding_key")
		}
		if strings.EqualFold(f.Severity, "HIGH") && !hasValidatedPrimitive(f) {
			v = append(v, tag+": HIGH without a validated exploit primitive (must cap to MEDIUM with escalation condition)")
		}
		if strings.EqualFold(f.Severity, "HIGH") && strings.Contains(strings.ToLower(f.ObservedEvidence), "unvalidated") {
			v = append(v, tag+": HIGH but observed evidence is marked unvalidated")
		}
		if f.ObservedEvidence != "" && len(f.EvidenceRefs) == 0 {
			v = append(v, tag+": has observed evidence but no immutable evidence reference")
		}
		// CVSS must be N/A for informational / negative evidence (CVSS describes a
		// vulnerability, not a control that held).
		if strings.EqualFold(f.Severity, "INFORMATIONAL") && !strings.Contains(cvssString(f), "N/A") {
			v = append(v, tag+": INFORMATIONAL finding shows a numeric CVSS (must be N/A)")
		}
		// remediation-family contamination: a non-crypto/non-auth finding must not
		// carry password-storage advice, and negative evidence must carry none.
		rem := strings.ToLower(remediationByType(f))
		if detectorOf(f) == "http.authz-boundary@1" && strings.TrimSpace(rem) != "" {
			v = append(v, tag+": negative-evidence finding has remediation text (must be none)")
		}
		if (strings.Contains(rem, "argon2") || strings.Contains(rem, "password")) &&
			f.KBClass != "auth-session" && f.KBClass != "crypto-secrets" && findingType(f) != "" {
			v = append(v, tag+": remediation family mismatch (password/crypto advice on a non-auth finding)")
		}
		// distinct conditions must not share one observation key
		ctl := observationControl(f) + "@" + assetOf(f)
		if prev, ok := seenObs[f.Key]; ok && prev != ctl {
			v = append(v, fmt.Sprintf("observation-key collision %s: %q vs %q", f.Key, prev, ctl))
		}
		seenObs[f.Key] = ctl
	}

	// ledger arithmetic
	for _, r := range buildLedger(live, findings) {
		if r.Passed+r.Failed != r.Tested {
			v = append(v, fmt.Sprintf("ledger %s: passed+failed(%d) != tested(%d)", r.Family, r.Passed+r.Failed, r.Tested))
		}
		if r.Tested+r.Inconclusive != r.Eligible {
			v = append(v, fmt.Sprintf("ledger %s: tested+inconclusive(%d) != eligible(%d)", r.Family, r.Tested+r.Inconclusive, r.Eligible))
		}
	}

	// screenshot count agreement
	if ss := strings.TrimSpace(readFileOr(joinWD(wd, "screenshots-status.txt"), "")); strings.Contains(ss, "captured") {
		reported := 0
		fmt.Sscanf(ss, "%d captured", &reported)
		if actual := screenshotCount(wd); reported != actual {
			v = append(v, fmt.Sprintf("screenshot count mismatch: status=%d actual(recursive .png)=%d", reported, actual))
		}
	}

	// tool-version sanity in the attestation
	if m, ok := readRunMeta(wd); ok {
		for tool, ti := range m.ToolVersions {
			low := strings.ToLower(ti.Version)
			if strings.Contains(low, "usage") || strings.Contains(low, "[") || strings.Contains(ti.Version, "_") {
				v = append(v, fmt.Sprintf("tool %s: malformed version %q (use \"unknown\")", tool, ti.Version))
			}
		}
	}

	return v
}

func joinWD(wd, name string) string { return wd + "/" + name }

func readRunMeta(wd string) (RunMeta, bool) {
	b, err := os.ReadFile(joinWD(wd, "run-meta.json"))
	if err != nil {
		return RunMeta{}, false
	}
	var m RunMeta
	if json.Unmarshal(b, &m) != nil {
		return RunMeta{}, false
	}
	return m, true
}

// enforceReportLint runs the linter and returns an error listing violations, so
// report generation fails hard rather than shipping an inconsistent document.
func enforceReportLint(target, wd string, findings []Finding) error {
	if vs := reportLint(target, wd, findings); len(vs) > 0 {
		return fmt.Errorf("report linter blocked generation (%d violation(s)):\n  - %s", len(vs), strings.Join(vs, "\n  - "))
	}
	return nil
}

// normalizedForLint applies the same normalization the renderer does, so the
// linter checks exactly what will be rendered.
func normalizedForLint(target, wd string, fs []Finding) []Finding {
	for i := range fs {
		ensureEvidenceFields(&fs[i])
		enforceSeverityPolicy(&fs[i])
		if fs[i].Key == "" {
			fs[i].Key = observationKey(&fs[i])
		}
	}
	applyOverrides(target, fs)
	return fs
}
