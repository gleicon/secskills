package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/textutil"
)

// cmdOverride records a reviewer adjudication. It never edits a run file's
// automated verdict; it writes an append-only override keyed by finding_key.
func cmdOverride(args []string) error {
	fs := flag.NewFlagSet("override", flag.ContinueOnError)
	target := fs.String("target", "", "assessment target")
	key := fs.String("key", "", "stable finding_key to adjudicate")
	sev := fs.String("severity", "", "reviewed severity (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)")
	reviewer := fs.String("reviewer", finding.OSUser(), "reviewer identity")
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
	if b, err := os.ReadFile(filepath.Join(finding.StoreDir(*target), "latest")); err == nil {
		var run finding.Run
		json.Unmarshal(b, &run)
		for i := range run.Findings {
			if run.Findings[i].Key == *key {
				autoSev = run.Findings[i].Severity
				break
			}
		}
	}
	o := finding.Override{
		Key: *key, AutomatedSev: autoSev, ReviewedSev: strings.ToUpper(*sev),
		Reviewer: *reviewer, Timestamp: finding.NowRFC(), Reason: *reason, EvidenceRef: *evidence,
	}
	var list []finding.Override
	if b, err := os.ReadFile(finding.OverridesPath(*target)); err == nil {
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
	os.MkdirAll(finding.StoreDir(*target), 0o700)
	b, _ := json.MarshalIndent(list, "", "  ")
	if err := os.WriteFile(finding.OverridesPath(*target), b, 0o600); err != nil {
		return err
	}
	fmt.Printf("recorded override for %s: automated=%s reviewed=%s by %s\n", o.Key, textutil.OrNA(o.AutomatedSev), o.ReviewedSev, o.Reviewer)
	return nil
}
