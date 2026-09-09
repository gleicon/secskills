package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Finding mirrors the redteam-pentest findings-store schema (D-4).
type Finding struct {
	ID            string              `json:"id"`
	Title         string              `json:"title"`
	Host          string              `json:"host"`
	Severity      string              `json:"severity"`
	Status        string              `json:"status"` // open|mitigated|regressed|accepted|manual
	EvidenceCmd   string              `json:"evidence_cmd"`
	ExpectedOpen  string              `json:"expected_open_pattern"`
	LastResponse  string              `json:"last_response,omitempty"`
	ResponseHash  string              `json:"response_hash"`
	FirstSeenRun  string              `json:"first_seen_run"`
	LastTestedRun string              `json:"last_tested_run"`
	RetestHistory []map[string]string `json:"retest_history"`
	// Framework mapping (OWASP / CWE / cheatsheet / CVE) — filled by classify().
	OWASP      string   `json:"owasp,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
	KBClass    string   `json:"kb_class,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	References []string `json:"references,omitempty"`
	// Structured probe — how retest re-verifies the finding in Go, with no shell.
	// ProbeKind: header-missing | tls-weak | body-contains | status | manual.
	ProbeKind string `json:"probe_kind,omitempty"`
	ProbeURL  string `json:"probe_url,omitempty"`
	ProbeArg  string `json:"probe_arg,omitempty"`
	// Evidence/risk model (separate confidence from severity).
	// Confidence: Confirmed | High | Medium | Low.
	// Validation: exploited | behavior-confirmed | version-inferred | config-inferred | passive.
	Confidence string `json:"confidence,omitempty"`
	Validation string `json:"validation,omitempty"`
	// ImpactText is asset-specific, replacing the generic per-class string when set.
	ImpactText string `json:"impact,omitempty"`
	// ObservedEvidence is what the test actually observed (facts), distinct from
	// EvidenceCmd which is only a reproduction command.
	ObservedEvidence string `json:"observed_evidence,omitempty"`
	// Provenance: how this asset/finding was discovered and whether it is in scope.
	DiscoveredFrom string `json:"discovered_from,omitempty"`
	// Audit identity: DetectorID names the detector; Key is a stable hash so a
	// finding persists across runs (open→mitigated→regressed) independent of F-NNN.
	DetectorID string `json:"detector_id,omitempty"`
	Key        string `json:"finding_key,omitempty"`      // observation identity (asset+detector+condition)
	RootKey    string `json:"root_finding_key,omitempty"` // collapse identity (asset+detector family)
	// Formal evidence state (state machine) + immutable evidence object ids.
	State        string   `json:"evidence_state,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	// Severity provenance: automated (rubric) severity is immutable; a human
	// adjudication is recorded separately, never by mutating Severity.
	AutomatedSeverity string    `json:"automated_severity,omitempty"`
	Override          *Override `json:"override,omitempty"`
	// HIGH-invariant support: when a nominal HIGH lacks a validated exploit
	// primitive, severity is capped and the escalation condition is recorded.
	PotentialSeverity   string `json:"potential_severity,omitempty"`
	EscalationCondition string `json:"escalation_condition,omitempty"`
	// per-observation time (audit forensics): exact capture time of the evidence.
	ObservedAt  string `json:"observed_at,omitempty"`
	FirstSeen   string `json:"first_seen,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
	FixedAt     string `json:"fixed_at,omitempty"`
	RegressedAt string `json:"regressed_at,omitempty"`
	// Adversarial model: capabilities this finding grants an attacker (drives the
	// attack graph), and any pivot intelligence extracted from it.
	Capabilities []string `json:"capabilities,omitempty"`
	Pivots       []string `json:"pivots,omitempty"`
}

type Run struct {
	RunID         string         `json:"run_id"`
	Target        string         `json:"target"`
	Date          string         `json:"date"`
	Type          string         `json:"type"`
	PreviousRunID string         `json:"previous_run_id,omitempty"`
	FindingCounts map[string]int `json:"finding_counts"`
	StatusCounts  map[string]int `json:"status_counts,omitempty"`
	Findings      []Finding      `json:"findings"`
}

func nowRFC() string { return time.Now().UTC().Format(time.RFC3339) }

func storeDir(target string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secskills-findings", target)
}

func runID(target string, count int) string {
	h := sha256.Sum256([]byte(target + time.Now().UTC().Format(time.RFC3339) + fmt.Sprint(count)))
	return time.Now().UTC().Format("20060102-1504") + "-" + fmt.Sprintf("%x", h[:2])
}

// cmdReport handles --retest (re-probe latest run) for now; full render is
// documented in lib/report-template.md and produced by the model from findings.
func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	retest := fs.String("retest", "", "target to re-probe against its latest run")
	render := fs.String("render", "", "target: render a markdown report from its findings")
	htmlT := fs.String("html", "", "target: render a professional HTML report")
	pdfT := fs.String("pdf", "", "target: render a professional PDF report (needs headless Chrome)")
	auditT := fs.String("audit", "", "target: render a concise auditor evidence report (control objectives + ledger + attestation)")
	lintT := fs.String("lint", "", "target: run the report-generation linter (invariants) and report violations")
	output := fs.String("output", "", "write rendered report to this path (default stdout/auto)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *retest != "":
		return doRetest(*retest)
	case *render != "":
		return doRender(*render, *output)
	case *htmlT != "":
		return writeHTMLReport(*htmlT, workdir(*htmlT), *output)
	case *pdfT != "":
		return writePDFReport(*pdfT, workdir(*pdfT), *output)
	case *auditT != "":
		return doAudit(*auditT, *output)
	case *lintT != "":
		wd := workdir(*lintT)
		vs := reportLint(*lintT, wd, normalizedForLint(*lintT, wd, loadOrLatest(*lintT, wd)))
		if len(vs) == 0 {
			fmt.Println("report lint: clean")
			return nil
		}
		return fmt.Errorf("report lint: %d violation(s):\n  - %s", len(vs), strings.Join(vs, "\n  - "))
	default:
		return fmt.Errorf("usage: secskills report --render|--html|--pdf|--audit <target> [--output f] | --retest <target>")
	}
}

// doRender assembles a human-readable markdown report from the workdir findings
// (or the latest persisted run), following lib/report-template.md.
func doRender(target, output string) error {
	wd := workdir(target)
	findings := loadWorkFindings(wd)
	if len(findings) == 0 {
		if b, err := os.ReadFile(filepath.Join(storeDir(target), "latest")); err == nil {
			var run Run
			json.Unmarshal(b, &run)
			findings = run.Findings
		}
	}
	if err := enforceReportLint(target, wd, normalizedForLint(target, wd, findings)); err != nil {
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

// severityOrder ranks severities most-severe first; shared by every sort/collapse.
var severityOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return severityOrder[fs[i].Severity] < severityOrder[fs[j].Severity] })
}

func doRetest(target string) error {
	latest := filepath.Join(storeDir(target), "latest")
	raw, err := os.ReadFile(latest)
	if err != nil {
		return fmt.Errorf("no prior run for %s (%v) — run a full assessment with save first", target, err)
	}
	var prev Run
	if err := json.Unmarshal(raw, &prev); err != nil {
		return err
	}
	newID := runID(target, len(prev.Findings))
	fmt.Printf("=== RETEST: %s (%s -> %s) ===\n", target, prev.RunID, newID)
	fmt.Println("| ID | Severity | Status | Change | Title |")
	fmt.Println("|----|----------|--------|--------|-------|")
	status := map[string]int{}
	for i := range prev.Findings {
		f := &prev.Findings[i]
		prevStatus := f.Status
		// Structured re-verification in Go — no shell, no eval. EvidenceCmd is a
		// human-readable reproduction string only and is never executed.
		state, evidence := reprobe(f)
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
				f.RegressedAt = nowRFC()
			} else {
				f.Status, disposition, change = "open", "OPEN", "✗ still open"
			}
		default: // mitigated
			f.Status, disposition, change = "mitigated", "FIXED", "✓ fixed"
			if f.FixedAt == "" {
				f.FixedAt = nowRFC()
			}
		}
		f.LastSeen = nowRFC()
		f.LastTestedRun = newID
		f.RetestHistory = append(f.RetestHistory, map[string]string{
			"run_id": newID, "date": nowRFC(), "disposition": disposition,
			"change": change, "retest_evidence": evidence, "prev_status": prevStatus,
		})
		status[disposition]++
		fmt.Printf("| %s | %s | %s | %s | %s |\n", f.ID, f.Severity, disposition, change, f.Title)
	}
	prev.RunID, prev.PreviousRunID, prev.Type = newID, prev.RunID, "retest"
	prev.Date = time.Now().UTC().Format(time.RFC3339)
	prev.StatusCounts = status
	out, _ := json.MarshalIndent(prev, "", "  ")
	newFile := filepath.Join(storeDir(target), "run-"+newID+".json")
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
