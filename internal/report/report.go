package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/workspace"
)

// DoRender assembles a human-readable markdown report from the workdir findings
// (or the latest persisted run), following lib/report-template.md.
func DoRender(target, output string) error {
	wd := workspace.Workdir(target)
	findings := finding.LoadWorkFindings(wd)
	if len(findings) == 0 {
		if b, err := os.ReadFile(filepath.Join(finding.StoreDir(target), "latest")); err == nil {
			var run finding.Run
			json.Unmarshal(b, &run)
			findings = run.Findings
		}
	}
	if err := enforceReportLint(target, wd, NormalizedForLint(target, wd, findings)); err != nil {
		return err
	}
	report := renderProReport(target, wd, findings)
	report += fmt.Sprintf("\n---\n_Report SHA-256: %x_\n", sha256.Sum256([]byte(report)))
	if output == "" {
		fmt.Print(report)
		return nil
	}
	return os.WriteFile(output, []byte(report), 0o644)
}

// DoRetest re-probes every finding of the latest run and prints the deltas.
func DoRetest(target string) error {
	latest := filepath.Join(finding.StoreDir(target), "latest")
	raw, err := os.ReadFile(latest)
	if err != nil {
		return fmt.Errorf("no prior run for %s (%v) — run a full assessment with save first", target, err)
	}
	var prev finding.Run
	if err := json.Unmarshal(raw, &prev); err != nil {
		return err
	}
	newID := finding.RunID(target, len(prev.Findings))
	fmt.Printf("=== RETEST: %s (%s -> %s) ===\n", target, prev.RunID, newID)
	fmt.Println("| ID | Severity | Status | Change | Title |")
	fmt.Println("|----|----------|--------|--------|-------|")
	status := map[string]int{}
	for i := range prev.Findings {
		f := &prev.Findings[i]
		prevStatus := f.Status
		// Structured re-verification in Go — no shell, no eval. EvidenceCmd is a
		// human-readable reproduction string only and is never executed.
		state, evidence := engine.Reprobe(f)
		var disposition, change string
		switch state {
		case "inconclusive":
			// never silently "fixed": an unreachable/errored probe is INCONCLUSIVE.
			f.Status, disposition, change = "inconclusive", "INCONCLUSIVE", "? inconclusive"
		case "manual":
			f.Status, disposition, change = "manual", "MANUAL", "· manual recheck"
		case "open":
			if prevStatus == "mitigated" {
				f.Status, disposition, change = "open", "REGRESSED", "↑ regressed"
				f.RegressedAt = finding.NowRFC()
			} else {
				f.Status, disposition, change = "open", "OPEN", "✗ still open"
			}
		default: // mitigated
			f.Status, disposition, change = "mitigated", "FIXED", "✓ fixed"
			if f.FixedAt == "" {
				f.FixedAt = finding.NowRFC()
			}
		}
		f.LastSeen = finding.NowRFC()
		f.LastTestedRun = newID
		f.RetestHistory = append(f.RetestHistory, map[string]string{
			"run_id": newID, "date": finding.NowRFC(), "disposition": disposition,
			"change": change, "retest_evidence": evidence, "prev_status": prevStatus,
		})
		status[disposition]++
		fmt.Printf("| %s | %s | %s | %s | %s |\n", f.ID, f.Severity, disposition, change, f.Title)
	}
	prev.RunID, prev.PreviousRunID, prev.Type = newID, prev.RunID, "retest"
	prev.Date = time.Now().UTC().Format(time.RFC3339)
	prev.StatusCounts = status
	out, _ := json.MarshalIndent(prev, "", "  ")
	newFile := filepath.Join(finding.StoreDir(target), "run-"+newID+".json")
	if err := os.WriteFile(newFile, out, 0o600); err != nil {
		return err
	}
	os.Remove(latest)
	os.Symlink(newFile, latest)
	fmt.Println("\n=== SUMMARY ===")
	keys := make([]string, 0, len(status))
	for k := range status {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("%s: %d\n", k, status[k])
	}
	return nil
}
