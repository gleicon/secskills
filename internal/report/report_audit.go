package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/tooling"
	"github.com/gleicon/secskills/internal/workspace"
)

// DoAudit renders the concise external-auditor evidence report and also emits a
// machine-readable attestation.json alongside it. This is the short, evidence-
// optimized deliverable (the full technical report is a separate archive) — item
// 25/26 of the audit-grade review: don't hand an auditor 500 pages by default.
func DoAudit(target, output string) error {
	wd := workspace.Workdir(target)
	findings := LoadOrLatest(target, wd)
	for i := range findings {
		finding.EnsureEvidenceFields(&findings[i])
	}
	live := tooling.LiveHosts(wd)

	// machine-readable attestation next to the report (CycloneDX/VEX-style intent)
	if b, err := os.ReadFile(filepath.Join(wd, "run-meta.json")); err == nil {
		var m finding.RunMeta
		if json.Unmarshal(b, &m) == nil {
			scores, _ := engine.RunConformance()
			scorecard := map[string]any{}
			for fam, sc := range scores {
				scorecard[fam] = map[string]any{"precision": engine.Precision(sc), "recall": engine.Recall(sc), "tp": sc.TP, "fp": sc.FP, "fn": sc.FN}
			}
			att := map[string]any{
				"attestation":        m,
				"controls":           finding.BuildLedger(live, findings),
				"finding_count":      len(findings),
				"findings":           auditFindingRefs(findings),
				"detector_registry":  finding.DetectorRegistry(),
				"detector_scorecard": scorecard,
				"evidence_manifest":  finding.LoadEvidenceManifest(wd),
			}
			ab, _ := json.MarshalIndent(att, "", "  ")
			os.WriteFile(filepath.Join(wd, "attestation.json"), ab, 0o644)
		}
	}

	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("# External Control-Verification Evidence — %s\n\n", target)
	p("**Classification:** Confidential — Authorized Recipients Only  \n")
	p("**Deliverable:** Concise auditor evidence report (companion to the full technical findings report and the raw evidence bundle).\n\n---\n\n")

	p("## Control objective\n\n")
	p("Verify, from an external unauthenticated position, the state of common web security controls (transport security, security headers, unauthenticated exposure, cross-origin policy) across the in-scope external attack surface. No authenticated or destructive testing was performed.\n\n")

	p("## Scope & test population\n\n")
	p("| Item | Value |\n|------|------:|\n")
	p("| In-scope apex | %s |\n", target)
	p("| Live HTTP/S services assessed | %d |\n\n", len(live))

	p("## Control test results\n\n%s\n\n", finding.RenderLedger(live, findings))

	p("## Exceptions (control failures requiring remediation)\n\n")
	p("Observations collapse to the following root issues:\n\n%s\n\n", rootIssues(findings))

	p("## Retest status\n\n%s\n\n", auditRetestLine(target))

	p("## Run attestation\n\n%s\n\n", finding.RenderAttestation(wd))
	p("## Evidence references\n\n")
	p("- Findings (stable keys): `data/findings-%s.json`\n", target)
	p("- Machine-readable attestation: `attestation.json` (run + control ledger + finding refs, hashed)\n")
	p("- Raw evidence bundle (subdomains, live services, nuclei, TLS, screenshots): `data/` — hashed in the attestation.\n\n")
	report := b.String()
	report += "\n---\n_Report SHA-256: (computed at archive time)_\n"

	if output == "" {
		fmt.Print(report)
		return nil
	}
	return os.WriteFile(output, []byte(report), 0o644)
}

func auditRetestLine(target string) string {
	b, err := os.ReadFile(filepath.Join(finding.StoreDir(target), "latest"))
	if err != nil {
		return "No prior run on record — this is a baseline assessment. Retest with `secskills report --retest " + target + "` to produce disposition deltas (FIXED/OPEN/REGRESSED/INCONCLUSIVE) keyed by stable finding key."
	}
	var run finding.Run
	if json.Unmarshal(b, &run) != nil {
		return "Not available."
	}
	if run.Type == "retest" {
		return fmt.Sprintf("This run is a retest of `%s`. See the Retest Delta Report in the full technical report for per-key dispositions.", run.PreviousRunID)
	}
	return "Baseline run `" + run.RunID + "`. Retest available via `secskills report --retest " + target + "`."
}

// auditFindingRefs is the finding view an external governance system ingests:
// stable identity + severity + evidence state, without the prose.
func auditFindingRefs(fs []finding.Finding) []map[string]string {
	out := make([]map[string]string, 0, len(fs))
	for i := range fs {
		f := &fs[i]
		out = append(out, map[string]string{
			"finding_key": f.Key,
			"detector_id": finding.DetectorIDFor(f),
			"asset":       f.Host,
			"severity":    f.Severity,
			"confidence":  f.Confidence,
			"validation":  f.Validation,
			"status":      f.Status,
		})
	}
	return out
}
