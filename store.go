package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// workFindings is the incremental findings file inside the assessment workdir.
func workFindings(wd string) string { return filepath.Join(wd, "findings.json") }

// loadWorkFindings reads the in-progress findings for an assessment.
func loadWorkFindings(wd string) []Finding {
	b, err := os.ReadFile(workFindings(wd))
	if err != nil {
		return nil
	}
	var fs []Finding
	json.Unmarshal(b, &fs)
	return fs
}

// addFinding appends/updates a finding in the workdir (dedup by ID). It runs the
// evidence command once to capture the current response hash for later retest.
func addFinding(wd string, f Finding) error {
	if f.Status == "" {
		f.Status = "open"
	}
	// Note: the response hash is captured lazily at first retest (which re-runs
	// evidence_cmd) — avoid re-executing every finding's command at write time,
	// which would add one request per finding.
	if f.RetestHistory == nil {
		f.RetestHistory = []map[string]string{}
	}
	existing := loadWorkFindings(wd)
	replaced := false
	for i := range existing {
		if existing[i].ID == f.ID {
			existing[i] = f
			replaced = true
			break
		}
	}
	if !replaced {
		existing = append(existing, f)
	}
	b, _ := json.MarshalIndent(existing, "", "  ")
	return os.WriteFile(workFindings(wd), b, 0o600)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// writeRun freezes the workdir findings into a persistent run file and updates
// the `latest` symlink (D-4). Returns the run file path.
func writeRun(target, wd, runType string) (string, error) {
	fs := loadWorkFindings(wd)
	dir := storeDir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	id := runID(target, len(fs))
	for i := range fs {
		if fs[i].FirstSeenRun == "" {
			fs[i].FirstSeenRun = id
		}
		fs[i].LastTestedRun = id
	}
	run := Run{
		RunID: id, Target: target, Date: nowRFC(), Type: runType,
		FindingCounts: countBy(fs, func(f Finding) string { return f.Severity }),
		Findings:      fs,
	}
	b, _ := json.MarshalIndent(run, "", "  ")
	path := filepath.Join(dir, "run-"+id+".json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	latest := filepath.Join(dir, "latest")
	os.Remove(latest)
	os.Symlink(path, latest)
	return path, nil
}

func countBy(fs []Finding, key func(Finding) string) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[key(f)]++
	}
	return m
}

func cmdFindings(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills findings <add|write-run|list|show> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return findingsAdd(rest)
	case "write-run":
		return findingsWriteRun(rest)
	case "list":
		return findingsList(rest)
	case "show":
		return findingsShow(rest)
	default:
		return fmt.Errorf("unknown findings subcommand %q", sub)
	}
}

func findingsAdd(args []string) error {
	fs := flag.NewFlagSet("findings add", flag.ContinueOnError)
	target := fs.String("target", "", "assessment target (for workdir)")
	id := fs.String("id", "", "finding id, e.g. FINDING-01")
	title := fs.String("title", "", "short title")
	host := fs.String("host", "", "affected host/URL or file:line")
	sev := fs.String("severity", "MEDIUM", "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL")
	ev := fs.String("evidence-cmd", "", "single command that reproduces the observable")
	expect := fs.String("expected", "", "pattern that marks the finding still-open")
	status := fs.String("status", "open", "open|mitigated|manual|accepted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *id == "" || *title == "" {
		return fmt.Errorf("required: --target --id --title")
	}
	wd := workdir(*target)
	return addFinding(wd, Finding{
		ID: *id, Title: *title, Host: *host, Severity: strings.ToUpper(*sev),
		Status: *status, EvidenceCmd: *ev, ExpectedOpen: *expect,
	})
}

func findingsWriteRun(args []string) error {
	fs := flag.NewFlagSet("findings write-run", flag.ContinueOnError)
	target := fs.String("target", "", "assessment target")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("required: --target")
	}
	wd := workdir(*target)
	path, err := writeRun(*target, wd, "full")
	if err != nil {
		return err
	}
	fmt.Printf("run written: %s (%d findings)\n", path, len(loadWorkFindings(wd)))
	return nil
}

func findingsList(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills findings list <target>")
	}
	dir := storeDir(args[0])
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("no runs for %s", args[0])
	}
	var runs []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "run-") {
			runs = append(runs, e.Name())
		}
	}
	sort.Strings(runs)
	for _, r := range runs {
		fmt.Println("  " + r)
	}
	return nil
}

func findingsShow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills findings show <target>")
	}
	b, err := os.ReadFile(filepath.Join(storeDir(args[0]), "latest"))
	if err != nil {
		return fmt.Errorf("no latest run for %s", args[0])
	}
	os.Stdout.Write(b)
	return nil
}
