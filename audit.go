package main

import (
	"time"
	"context"
	"net"
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
	ScopeSHA     string `json:"scope_manifest_sha256"`
	ConfigSHA    string `json:"config_sha256"`
	RulesetSHA   string `json:"ruleset_sha256"`
	EvidenceSHA  string `json:"raw_evidence_bundle_sha256"`
	SourceIP     string `json:"scanner_source_ip"`
	ToolVersions map[string]string `json:"tool_versions"`
}

func writeRunMeta(wd, target, started string, findings []Finding, deep, intrusive bool) {
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
		ScopeSHA:      scopeSHA(wd),
		ConfigSHA:     configSHA(target, deep, intrusive),
		RulesetSHA:    rulesetSHA(),
		EvidenceSHA:   evidenceBundleSHA(wd),
		SourceIP:      egressIP(),
		ToolVersions:  toolVersions(),
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	os.WriteFile(filepath.Join(wd, "run-meta.json"), mb, 0o644)
}

// scopeSHA hashes the normalized (sorted, deduped) scope manifest, so the
// attestation binds the report to the exact target set that was assessed.
func scopeSHA(wd string) string {
	lines := readLines(filepath.Join(wd, "scope.txt"))
	norm := make([]string, 0, len(lines))
	seen := map[string]bool{}
	for _, l := range lines {
		l = strings.ToLower(strings.TrimSpace(l))
		if l != "" && !seen[l] {
			seen[l] = true
			norm = append(norm, l)
		}
	}
	sort.Strings(norm)
	sum := sha256.Sum256([]byte(strings.Join(norm, "\n")))
	return fmt.Sprintf("%x", sum)
}

// configSHA hashes the run configuration (target + phase flags) that affects
// which detectors ran, so two runs are comparable only when config matches.
func configSHA(target string, deep, intrusive bool) string {
	cfg := fmt.Sprintf("target=%s;deep=%t;intrusive=%t;engine=%s", target, deep, intrusive, version)
	sum := sha256.Sum256([]byte(cfg))
	return fmt.Sprintf("%x", sum)
}

// rulesetSHA hashes the detector-pack identity manifest — the set of detector
// IDs the engine can emit. A detector-pack change moves this hash, which is how
// an auditor detects that finding semantics may have changed between runs.
func rulesetSHA() string {
	sum := sha256.Sum256([]byte(strings.Join(detectorManifest(), "\n")))
	return fmt.Sprintf("%x", sum)
}

// detectorManifest is the stable list of detector IDs this build ships. Update
// this alongside detectorIDFor so the ruleset hash tracks detector changes.
func detectorManifest() []string {
	return []string{
		"tls.deprecated-protocol@1",
		"http.header.hsts-missing@1",
		"http.header.csp-missing@1",
		"http.header.nosniff-missing@1",
		"http.header.xfo-missing@1",
		"http.cors@1",
		"http.prometheus.public-metrics@1",
		"http.exposure-path@1",
		"component.banner-osv-correlation@1",
		"content.prompt-injection@1",
		"nuclei@1",
		"generic@1",
	}
}

// evidenceBundleSHA hashes the raw-evidence artifacts in the workdir (findings,
// nuclei output, sslscan/shodan data, screenshot filenames), so the attestation
// covers the evidence bundle, not just the findings summary.
func evidenceBundleSHA(wd string) string {
	h := sha256.New()
	arts := []string{"findings.json", "nuclei.jsonl", "resolved.txt", "ips.txt", "live_hosts.json", "subs.txt"}
	sort.Strings(arts)
	for _, a := range arts {
		if b, err := os.ReadFile(filepath.Join(wd, a)); err == nil {
			fmt.Fprintf(h, "%s:%x\n", a, sha256.Sum256(b))
		}
	}
	// screenshot inventory (filenames + sizes), not the image bytes
	if ents, err := os.ReadDir(filepath.Join(wd, "screenshots")); err == nil {
		var names []string
		for _, e := range ents {
			if info, err := e.Info(); err == nil {
				names = append(names, fmt.Sprintf("%s:%d", e.Name(), info.Size()))
			}
		}
		sort.Strings(names)
		fmt.Fprintf(h, "screenshots:%s\n", strings.Join(names, ","))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// egressIP returns the scanner's outbound source IP as seen locally. It opens a
// UDP association to a public address (no packets are sent by connect()) to learn
// which local interface egress would use. Best-effort; empty on failure.
func egressIP() string {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// toolVersions records the version of each external tool present, so the
// attestation captures tool identity (not just names) for reproducibility.
func toolVersions() map[string]string {
	out := map[string]string{}
	probes := map[string][]string{
		"subfinder": {"-version"}, "dnsx": {"-version"}, "httpx": {"-version"},
		"nuclei": {"-version"}, "sslscan": {"--version"}, "ast-grep": {"--version"},
	}
	for tool, args := range probes {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		b, _ := exec.CommandContext(ctx, tool, args...).CombinedOutput()
		cancel()
		v := strings.TrimSpace(firstNonEmptyLine(string(b)))
		if v == "" {
			v = "present"
		}
		out[tool] = v
	}
	return out
}

func firstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			return t
		}
	}
	return ""
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
	Family                                             string
	Eligible, Tested, Passed, Failed, Inconclusive, NA int
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
			r := rows[fam]
			// eligibility: TLS-version only applies to HTTPS endpoints; a plain
			// HTTP endpoint is Not-Applicable, not a silent gap.
			if fam == "tls-version" && !strings.HasPrefix(h.URL, "https://") {
				r.NA++
				continue
			}
			r.Eligible++
			if !reachable {
				// eligible but unreachable/errored at test time — INCONCLUSIVE,
				// never counted as passed/secure.
				r.Inconclusive++
				continue
			}
			r.Tested++
			if failed[hh+"|"+fam] {
				r.Failed++
			} else {
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
	b.WriteString("| Control family | Eligible | Tested | Passed | Failed | Inconclusive | N/A |\n|---|--:|--:|--:|--:|--:|--:|\n")
	var el, t, p, f, inc, na int
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %d |\n", r.Family, r.Eligible, r.Tested, r.Passed, r.Failed, r.Inconclusive, r.NA))
		el, t, p, f, inc, na = el+r.Eligible, t+r.Tested, p+r.Passed, f+r.Failed, inc+r.Inconclusive, na+r.NA
	}
	b.WriteString(fmt.Sprintf("| **Total** | **%d** | **%d** | **%d** | **%d** | **%d** | **%d** |\n", el, t, p, f, inc, na))
	b.WriteString("\n_Denominator semantics: **Eligible** = control applies to the endpoint (TLS-version applies only to HTTPS; HTTP-only endpoints are **N/A**). **Tested** = eligible endpoints reachable at test time (Tested = Passed + Failed). **Inconclusive** = eligible but unreachable/errored — never counted as Passed/secure. Eligible = Tested + Inconclusive._")
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
	var tv strings.Builder
	tools := make([]string, 0, len(m.ToolVersions))
	for t := range m.ToolVersions {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	for _, t := range tools {
		fmt.Fprintf(&tv, "%s %s; ", t, m.ToolVersions[t])
	}
	return fmt.Sprintf(
		"| Field | Value |\n|-------|-------|\n"+
			"| Run ID | `%s` |\n| Target | %s |\n| Started | %s |\n| Finished | %s |\n"+
			"| Engine | secskills v%s |\n| Build commit | `%s` |\n| Operator | %s |\n"+
			"| Scanner source IP | `%s` |\n"+
			"| Tool versions | %s |\n"+
			"| Authorization | %s |\n"+
			"| Scope manifest SHA-256 | `%s` |\n"+
			"| Config SHA-256 | `%s` |\n"+
			"| Ruleset (detector-pack) SHA-256 | `%s` |\n"+
			"| Findings SHA-256 | `%s` |\n"+
			"| Raw evidence bundle SHA-256 | `%s` |\n\n"+
			"_This binds the report to an exact run, engine build, and the normalized scope manifest (hashed above). The findings, evidence bundle, ruleset, and config are each independently hashed; the report's own SHA-256 is printed in the document footer for cross-reference._",
		m.RunID, m.Target, m.Started, m.Finished, m.EngineVer, m.GitCommit, m.Operator,
		orNA(m.SourceIP), orNA(tv.String()), m.Authorization,
		m.ScopeSHA, m.ConfigSHA, m.RulesetSHA, m.FindingsSHA, m.EvidenceSHA)
}

func orNA(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ";"))
}
