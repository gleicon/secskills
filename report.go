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
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Host              string   `json:"host"`
	Severity          string   `json:"severity"`
	Status            string   `json:"status"` // open|mitigated|regressed|accepted|manual
	EvidenceCmd       string   `json:"evidence_cmd"`
	ExpectedOpen      string   `json:"expected_open_pattern"`
	LastResponse      string   `json:"last_response,omitempty"`
	ResponseHash      string   `json:"response_hash"`
	FirstSeenRun      string   `json:"first_seen_run"`
	LastTestedRun     string   `json:"last_tested_run"`
	RetestHistory     []map[string]string `json:"retest_history"`
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
	default:
		return fmt.Errorf("usage: secskills report --render|--html|--pdf <target> [--output f] | --retest <target>")
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
	report := renderProReport(target, wd, findings)
	if output == "" {
		fmt.Print(report)
		return nil
	}
	return os.WriteFile(output, []byte(report), 0o644)
}

func sortFindings(fs []Finding) {
	rank := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
	sort.SliceStable(fs, func(i, j int) bool { return rank[fs[i].Severity] < rank[fs[j].Severity] })
}

// kbClassFor maps a finding title to a KB class for the remediation pointer.
func kbClassFor(title string) string {
	t := strings.ToLower(title)
	switch {
	case strings.Contains(t, "hsts") || strings.Contains(t, "tls") || strings.Contains(t, "cipher") || strings.Contains(t, "cookie"):
		return "crypto-secrets"
	case strings.Contains(t, "csp") || strings.Contains(t, "header") || strings.Contains(t, "cors") || strings.Contains(t, "clickjack") || strings.Contains(t, "exposed") || strings.Contains(t, "metrics") || strings.Contains(t, "actuator"):
		return "config-exposure"
	case strings.Contains(t, "xss") || strings.Contains(t, "inject") || strings.Contains(t, "sql"):
		return "injection"
	case strings.Contains(t, "ssrf") || strings.Contains(t, "xxe"):
		return "ssrf-xxe"
	case strings.Contains(t, "auth") || strings.Contains(t, "session") || strings.Contains(t, "password"):
		return "auth-session"
	default:
		return "top10"
	}
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
		change := "—"
		// Structured re-verification in Go — no shell, no eval. EvidenceCmd is a
		// human-readable reproduction string only and is never executed.
		stillOpen, testable := reprobe(f)
		if !testable {
			f.Status = "manual"
		} else {
			switch {
			case stillOpen && f.Status == "mitigated":
				f.Status, change = "regressed", "↑ REGRESSED"
			case stillOpen:
				f.Status, change = "open", "✗ still open"
			default:
				f.Status, change = "mitigated", "✓ mitigated"
			}
		}
		f.LastTestedRun = newID
		// close the loop in writing: append a verification note to the finding
		// rather than issuing a disconnected fresh report (playbook §05).
		verdict := f.Status
		if !testable {
			verdict = "manual-recheck-needed"
		}
		f.RetestHistory = append(f.RetestHistory, map[string]string{
			"run_id": newID, "date": nowRFC(), "status": verdict, "change": strings.TrimSpace(change),
		})
		status[f.Status]++
		fmt.Printf("| %s | %s | %s | %s | %s |\n", f.ID, f.Severity, f.Status, change, f.Title)
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
