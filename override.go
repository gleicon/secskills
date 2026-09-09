package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Item 12 — Auditable human adjudication.
// Automation never silently mutates a result. A reviewer's severity change is
// recorded as a separate, immutable Override attached to the finding, keyed by
// the stable finding_key. The report shows both the automated and reviewed
// severity with reviewer, timestamp, and reason.
type Override struct {
	Key          string `json:"finding_key"`
	AutomatedSev string `json:"automated_severity"`
	ReviewedSev  string `json:"reviewed_severity"`
	Reviewer     string `json:"reviewer"`
	Timestamp    string `json:"timestamp"`
	Reason       string `json:"reason"`
	EvidenceRef  string `json:"evidence_ref,omitempty"`
}

func overridesPath(target string) string {
	return filepath.Join(storeDir(target), "overrides.json")
}

func loadOverrides(target string) map[string]Override {
	out := map[string]Override{}
	b, err := os.ReadFile(overridesPath(target))
	if err != nil {
		return out
	}
	var list []Override
	json.Unmarshal(b, &list)
	for _, o := range list {
		out[o.Key] = o
	}
	return out
}

// applyOverrides attaches recorded overrides to findings without changing the
// automated severity: Severity holds the effective (reviewed) value for display,
// AutomatedSeverity preserves the machine verdict, and Override carries the trail.
func applyOverrides(target string, fs []Finding) {
	ov := loadOverrides(target)
	if len(ov) == 0 {
		return
	}
	for i := range fs {
		f := &fs[i]
		o, ok := ov[f.Key]
		if !ok {
			continue
		}
		f.AutomatedSeverity = f.Severity
		oc := o
		f.Override = &oc
		f.Severity = o.ReviewedSev
	}
}

// cmdOverride records a reviewer adjudication. It never edits a run file's
// automated verdict; it writes an append-only override keyed by finding_key.
func cmdOverride(args []string) error {
	fs := flag.NewFlagSet("override", flag.ContinueOnError)
	target := fs.String("target", "", "assessment target")
	key := fs.String("key", "", "stable finding_key to adjudicate")
	sev := fs.String("severity", "", "reviewed severity (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)")
	reviewer := fs.String("reviewer", osUser(), "reviewer identity")
	reason := fs.String("reason", "", "justification for the adjudication")
	evidence := fs.String("evidence", "", "evidence ref supporting the change (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *key == "" || *sev == "" || *reason == "" {
		return fmt.Errorf("required: --target --key --severity --reason")
	}
	// find the automated severity from the latest run
	autoSev := ""
	if b, err := os.ReadFile(filepath.Join(storeDir(*target), "latest")); err == nil {
		var run Run
		json.Unmarshal(b, &run)
		for i := range run.Findings {
			if run.Findings[i].Key == *key {
				autoSev = run.Findings[i].Severity
				break
			}
		}
	}
	o := Override{
		Key: *key, AutomatedSev: autoSev, ReviewedSev: strings.ToUpper(*sev),
		Reviewer: *reviewer, Timestamp: nowRFC(), Reason: *reason, EvidenceRef: *evidence,
	}
	var list []Override
	if b, err := os.ReadFile(overridesPath(*target)); err == nil {
		json.Unmarshal(b, &list)
	}
	replaced := false
	for i := range list {
		if list[i].Key == o.Key {
			list[i] = o
			replaced = true
		}
	}
	if !replaced {
		list = append(list, o)
	}
	os.MkdirAll(storeDir(*target), 0o700)
	b, _ := json.MarshalIndent(list, "", "  ")
	if err := os.WriteFile(overridesPath(*target), b, 0o600); err != nil {
		return err
	}
	fmt.Printf("recorded override for %s: automated=%s reviewed=%s by %s\n", o.Key, orNA(o.AutomatedSev), o.ReviewedSev, o.Reviewer)
	return nil
}

// renderOverrideNote renders the adjudication trail for a finding, if present.
func renderOverrideNote(f *Finding) string {
	if f.Override == nil {
		return ""
	}
	o := f.Override
	return fmt.Sprintf("Automated severity **%s** → reviewed **%s** by %s at %s. Reason: %s%s",
		orNA(o.AutomatedSev), o.ReviewedSev, safeField(o.Reviewer), o.Timestamp, safeField(o.Reason),
		func() string {
			if o.EvidenceRef != "" {
				return " (evidence: `" + o.EvidenceRef + "`)"
			}
			return ""
		}())
}
