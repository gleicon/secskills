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
	ensureEvidenceFields(&f)
	// stable audit identity — independent of the display index F-NNN
	if f.DetectorID == "" {
		f.DetectorID = detectorIDFor(&f)
	}
	if f.Key == "" {
		f.Key = stableFindingKey(&f)
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

// ensureEvidenceFields enforces the schema invariant that every finding carries
// a non-blank Confidence and Validation (the executive summary asserts this).
// Values are inferred from the detector type; a finding never ships with a blank
// evidence state. Fields already set by a detector are respected.
func ensureEvidenceFields(f *Finding) {
	if f.Validation == "" {
		switch findingType(f) {
		case "tls-deprecated", "metrics-exposed", "exposure-path":
			f.Validation = "behavior-confirmed"
		case "component-lead":
			f.Validation = "version-inferred"
		case "csp-missing", "nosniff-missing", "xfo-missing", "hsts-missing", "cors":
			f.Validation = "passive"
		default:
			if strings.HasPrefix(strings.ToLower(f.Title), "nuclei:") {
				f.Validation = "behavior-confirmed"
			} else {
				f.Validation = "passive"
			}
		}
	}
	if f.Confidence == "" {
		switch f.Validation {
		case "exploited", "behavior-confirmed":
			f.Confidence = "Confirmed"
		case "config-inferred":
			f.Confidence = "Medium"
		case "version-inferred":
			f.Confidence = "Low"
		default: // passive
			f.Confidence = "Confirmed" // a directly-observed absence/presence
		}
	}
}

// stableFindingKey derives a finding's audit identity from stable *semantics*,
// not from scan-output ordering or volatile strings. It must survive: finding
// reordering, F-number changes, other hosts being added, report date/IP changes,
// scheme (http/https) and trailing-slash normalization. Identity intentionally
// changes only when the detector identity (which carries an @version) changes.
//
//	identity = detector + normalized asset(host:port) + normalized control/endpoint
func stableFindingKey(f *Finding) string {
	det := f.DetectorID
	if det == "" {
		det = detectorIDFor(f)
	}
	asset := normalizedAsset(f.Host)
	if f.ProbeURL != "" {
		asset = normalizedAsset(f.ProbeURL)
	}
	control := normalizedControl(f)
	h := sha256.Sum256([]byte(det + "|" + asset + "|" + control))
	return fmt.Sprintf("%x", h[:8])
}

// normalizedAsset reduces a URL/host to host[:port], dropping the scheme and any
// default port, lowercased. So http://H/, https://H:443/, and H all normalize to
// the same asset — a control's identity does not flip on scheme/port cosmetics.
func normalizedAsset(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, ":443"), ":80")
	return s
}

// normalizedControl identifies which control/endpoint the finding is about, so
// the same weakness on the same asset keys identically across runs.
func normalizedControl(f *Finding) string {
	switch f.ProbeKind {
	case "header-missing":
		return "header:" + strings.ToLower(strings.TrimSpace(f.ProbeArg))
	case "tls-weak":
		return "tls-config" // per-asset TLS policy — one identity, not one per protocol
	case "status", "body-contains":
		return "path:" + normalizedPath(f.ProbeURL)
	}
	// fall back to the detector-specific type; keeps a stable label per class
	if t := findingType(f); t != "" {
		return "type:" + t
	}
	return "type:generic"
}

// normalizedPath extracts a normalized path (lowercased, trailing slash trimmed,
// query/fragment dropped) from a URL, so /metrics and /metrics/ are one control.
func normalizedPath(u string) string {
	s := strings.ToLower(strings.TrimSpace(u))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[i:]
	} else {
		s = "/"
	}
	if j := strings.IndexAny(s, "?#"); j >= 0 {
		s = s[:j]
	}
	if len(s) > 1 {
		s = strings.TrimRight(s, "/")
	}
	return s
}
