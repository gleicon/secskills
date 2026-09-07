package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// buildCommit is set at build time via -ldflags; falls back to a runtime git
// lookup so a dev build still records provenance.
var buildCommit = ""

func gitCommit() string {
	if buildCommit != "" {
		return buildCommit
	}
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// RunMeta is the run-attestation record: who/what/when produced this result, so
// an auditor can bind a report to an exact run, engine, and scope.
type RunMeta struct {
	RunID        string `json:"run_id"`
	Target       string `json:"target"`
	Started      string `json:"started"`
	Finished     string `json:"finished"`
	EngineVer    string `json:"engine_version"`
	GitCommit    string `json:"git_commit"`
	Operator     string `json:"operator"`
	Authorization string `json:"authorization"`
	FindingsSHA  string `json:"findings_sha256"`
}

func writeRunMeta(wd, target, started string, findings []Finding) {
	b, _ := json.Marshal(findings)
	sum := sha256.Sum256(b)
	m := RunMeta{
		RunID:         "run-" + runID(target, len(findings)),
		Target:        target,
		Started:       started,
		Finished:      nowRFC(),
		EngineVer:     version,
		GitCommit:     gitCommit(),
		Operator:      osUser(),
		Authorization: scopeAuthLine(target),
		FindingsSHA:   fmt.Sprintf("%x", sum),
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	os.WriteFile(filepath.Join(wd, "run-meta.json"), mb, 0o644)
}

func osUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

// ControlLedger records negative evidence: which controls were tested and passed,
// not only which failed — the audit-grade view an auditor trusts.
type ledgerRow struct {
	Family                              string
	Tested, Passed, Failed, Inconclusive int
}

// buildLedger derives the control-test ledger from the probed hosts and findings.
// A host with status 0 (unreachable at probe) yields inconclusive rows — a failed
// probe is never silently counted as "passed/secure".
func buildLedger(hosts []LiveHost, findings []Finding) []ledgerRow {
	families := []string{"security-headers", "tls-version", "unauth-exposure", "cors"}
	famOf := func(f *Finding) string {
		switch findingType(f) {
		case "hsts-missing", "csp-missing", "nosniff-missing", "xfo-missing":
			return "security-headers"
		case "tls-deprecated":
			return "tls-version"
		case "metrics-exposed", "exposure-path":
			return "unauth-exposure"
		case "cors":
			return "cors"
		}
		return ""
	}
	// (host,family) -> failed
	failed := map[string]bool{}
	for i := range findings {
		if fam := famOf(&findings[i]); fam != "" {
			failed[hostOf(findings[i].Host)+"|"+fam] = true
		}
	}
	rows := map[string]*ledgerRow{}
	for _, fam := range families {
		rows[fam] = &ledgerRow{Family: fam}
	}
	for _, h := range hosts {
		hh := hostOf(h.URL)
		reachable := h.Status > 0
		for _, fam := range families {
			if fam == "tls-version" && !strings.HasPrefix(h.URL, "https://") {
				continue
			}
			r := rows[fam]
			r.Tested++
			switch {
			case !reachable:
				r.Inconclusive++
			case failed[hh+"|"+fam]:
				r.Failed++
			default:
				r.Passed++
			}
		}
	}
	var out []ledgerRow
	for _, fam := range families {
		out = append(out, *rows[fam])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

// renderLedger renders the Control Test Ledger as a markdown table + totals.
func renderLedger(hosts []LiveHost, findings []Finding) string {
	rows := buildLedger(hosts, findings)
	var b strings.Builder
	b.WriteString("| Control family | Tested | Passed | Failed | Inconclusive |\n|---|--:|--:|--:|--:|\n")
	var t, p, f, inc int
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d |\n", r.Family, r.Tested, r.Passed, r.Failed, r.Inconclusive))
		t, p, f, inc = t+r.Tested, p+r.Passed, f+r.Failed, inc+r.Inconclusive
	}
	b.WriteString(fmt.Sprintf("| **Total** | **%d** | **%d** | **%d** | **%d** |\n", t, p, f, inc))
	b.WriteString("\n_Passed = control present / no weakness observed on a reachable host. Inconclusive = host unreachable or probe errored at test time (never counted as secure)._")
	return b.String()
}

// renderAttestation renders the Run Attestation section from run-meta.json.
func renderAttestation(wd string) string {
	b, err := os.ReadFile(filepath.Join(wd, "run-meta.json"))
	if err != nil {
		return "_Run attestation not available._"
	}
	var m RunMeta
	if json.Unmarshal(b, &m) != nil {
		return "_Run attestation not available._"
	}
	return fmt.Sprintf(
		"| Field | Value |\n|-------|-------|\n"+
			"| Run ID | `%s` |\n| Target | %s |\n| Started | %s |\n| Finished | %s |\n"+
			"| Engine | secskills v%s |\n| Build commit | `%s` |\n| Operator | %s |\n"+
			"| Authorization | %s |\n| Findings SHA-256 | `%s` |\n\n"+
			"_This binds the report to an exact run, engine build, and scope. The report's own SHA-256 is printed in the document footer for cross-reference._",
		m.RunID, m.Target, m.Started, m.Finished, m.EngineVer, m.GitCommit, m.Operator, m.Authorization, m.FindingsSHA)
}
