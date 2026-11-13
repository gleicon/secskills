package finding

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/workspace"
)

// WorkFindings is the incremental findings file inside the assessment workdir.
func WorkFindings(wd string) string { return filepath.Join(wd, "findings.json") }

// LoadWorkFindings reads the in-progress findings for an assessment.
func LoadWorkFindings(wd string) []Finding {
	b, err := os.ReadFile(WorkFindings(wd))
	if err != nil {
		return nil
	}
	var fs []Finding
	json.Unmarshal(b, &fs)
	return fs
}

// AddFinding appends/updates a finding in the workdir (dedup by ID). It runs the
// evidence command once to capture the current response hash for later retest.
func AddFinding(wd string, f Finding) error {
	if f.Status == "" {
		f.Status = "open"
	}
	EnsureEvidenceFields(&f)
	EnforceSeverityPolicy(&f)
	if len(f.Capabilities) == 0 {
		f.Capabilities = CapabilitiesFor(&f)
	}
	// stable audit identity — independent of the display index F-NNN
	if f.DetectorID == "" {
		f.DetectorID = DetectorIDFor(&f)
	}
	if f.Key == "" {
		f.Key = ObservationKey(&f) // unique per (asset, detector, condition)
	}
	if f.RootKey == "" {
		f.RootKey = rootFindingKey(&f) // per (asset, detector family) for collapse
	}
	// Note: the response hash is captured lazily at first retest (which re-runs
	// evidence_cmd) — avoid re-executing every finding's command at write time,
	// which would add one request per finding.
	if f.RetestHistory == nil {
		f.RetestHistory = []map[string]string{}
	}
	// Immutable evidence: bind every finding to a content-addressed evidence
	// object (item: finding -> evidence by ID, not "find the host's screenshot").
	if f.ObservedAt == "" {
		f.ObservedAt = NowRFC()
	}
	if f.FirstSeen == "" {
		f.FirstSeen = f.ObservedAt
	}
	f.LastSeen = f.ObservedAt
	if len(f.EvidenceRefs) == 0 && f.ObservedEvidence != "" {
		typ := "detector-parse"
		switch f.ProbeKind {
		case "header-missing":
			typ = "http-response"
		case "tls-weak":
			typ = "tls-transcript"
		case "status", "body-contains":
			typ = "http-response"
		}
		redaction := "none"
		if textutil.ReSecretish.MatchString(f.ObservedEvidence) {
			redaction = "redacted"
		}
		ev := CaptureEvidence(wd, DetectorOf(&f), AssetOf(&f), typ, "text/plain",
			f.ProbeKind+" "+f.ProbeURL+" @"+f.ObservedAt, redaction, []byte(f.ObservedEvidence))
		f.EvidenceRefs = []string{ev}
	}
	existing := LoadWorkFindings(wd)
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
	return os.WriteFile(WorkFindings(wd), b, 0o600)
}

// WriteRun freezes the workdir findings into a persistent run file and updates
// the `latest` symlink (D-4). Returns the run file path.
func WriteRun(target, wd, runType string) (string, error) {
	fs := LoadWorkFindings(wd)
	dir := StoreDir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	id := RunID(target, len(fs))
	for i := range fs {
		if fs[i].FirstSeenRun == "" {
			fs[i].FirstSeenRun = id
		}
		fs[i].LastTestedRun = id
	}
	run := Run{
		RunID: id, Target: target, Date: NowRFC(), Type: runType,
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

// FindingsAdd implements `findings add`.
func FindingsAdd(args []string) error {
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
	wd := workspace.Workdir(*target)
	return AddFinding(wd, Finding{
		ID: *id, Title: *title, Host: *host, Severity: strings.ToUpper(*sev),
		Status: *status, EvidenceCmd: *ev, ExpectedOpen: *expect,
	})
}

// FindingsWriteRun implements `findings write-run`.
func FindingsWriteRun(args []string) error {
	fs := flag.NewFlagSet("findings write-run", flag.ContinueOnError)
	target := fs.String("target", "", "assessment target")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("required: --target")
	}
	wd := workspace.Workdir(*target)
	path, err := WriteRun(*target, wd, "full")
	if err != nil {
		return err
	}
	fmt.Printf("run written: %s (%d findings)\n", path, len(LoadWorkFindings(wd)))
	return nil
}

// FindingsList implements `findings list`.
func FindingsList(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills findings list <target>")
	}
	dir := StoreDir(args[0])
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

// FindingsShow implements `findings show`.
func FindingsShow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills findings show <target>")
	}
	b, err := os.ReadFile(filepath.Join(StoreDir(args[0]), "latest"))
	if err != nil {
		return fmt.Errorf("no latest run for %s", args[0])
	}
	os.Stdout.Write(b)
	return nil
}

// EnsureEvidenceFields enforces the schema invariant that every finding carries
// a non-blank Confidence and Validation (the executive summary asserts this).
// Values are inferred from the detector type; a finding never ships with a blank
// evidence state. Fields already set by a detector are respected.
func EnsureEvidenceFields(f *Finding) {
	if f.Validation == "" {
		switch FindingType(f) {
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
	if f.State == "" {
		f.State = string(stateForValidation(f.Validation))
	}
}

// ObservationKey is a finding's precise audit identity: detector + normalized
// asset + the exact *condition* asserted. TLS 1.0 and TLS 1.1 on one host are
// DISTINCT observations (distinct keys), so a retest can mark one FIXED while the
// other stays OPEN. Survives finding reordering, F-number, scheme/slash/port/case.
func ObservationKey(f *Finding) string {
	det := DetectorOf(f)
	asset := AssetOf(f)
	h := sha256.Sum256([]byte(det + "|" + asset + "|" + ObservationControl(f)))
	return fmt.Sprintf("%x", h[:8])
}

// rootKey is the collapse identity: detector *family* + normalized asset, with
// the condition dropped. All deprecated-TLS observations on one host share a
// rootKey (the host's TLS policy), so the report collapses N observations into
// one root finding while each observation keeps its own observationKey.
func rootFindingKey(f *Finding) string {
	det := DetectorOf(f)
	asset := AssetOf(f)
	h := sha256.Sum256([]byte(det + "|" + asset + "|" + rootControl(f)))
	return fmt.Sprintf("%x", h[:8])
}

// DetectorOf returns the finding's detector id, deriving it when unset.
func DetectorOf(f *Finding) string {
	if f.DetectorID != "" {
		return f.DetectorID
	}
	return DetectorIDFor(f)
}

// AssetOf returns the normalized asset a finding is about.
func AssetOf(f *Finding) string {
	if f.ProbeURL != "" {
		return normalizedAsset(f.ProbeURL)
	}
	return normalizedAsset(f.Host)
}

// ObservationControl includes the exact condition (e.g. the TLS protocol version).
func ObservationControl(f *Finding) string {
	if f.ProbeKind == "tls-weak" {
		arg := strings.TrimSpace(f.ProbeArg)
		if arg == "" {
			// derive from title so combined weak-TLS findings still separate
			arg = strings.ToLower(f.Title)
		}
		return "tls:" + arg
	}
	return normalizedControl(f)
}

// rootControl drops the condition so a family collapses to one root per asset.
func rootControl(f *Finding) string {
	if f.ProbeKind == "tls-weak" {
		return "tls-config"
	}
	return normalizedControl(f)
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
	if t := FindingType(f); t != "" {
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
