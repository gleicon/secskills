package finding

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills/internal/textutil"
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

// OverridesPath is the overrides file for target.
func OverridesPath(target string) string {
	return filepath.Join(StoreDir(target), "overrides.json")
}

func loadOverrides(target string) map[string]Override {
	out := map[string]Override{}
	b, err := os.ReadFile(OverridesPath(target))
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

// ApplyOverrides attaches recorded overrides to findings without changing the
// automated severity: Severity holds the effective (reviewed) value for display,
// AutomatedSeverity preserves the machine verdict, and Override carries the trail.
func ApplyOverrides(target string, fs []Finding) {
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

// RenderOverrideNote renders the adjudication trail for a finding, if present.
func RenderOverrideNote(f *Finding) string {
	if f.Override == nil {
		return ""
	}
	o := f.Override
	return fmt.Sprintf("Automated severity **%s** → reviewed **%s** by %s at %s. Reason: %s%s",
		textutil.OrNA(o.AutomatedSev), o.ReviewedSev, textutil.SafeField(o.Reviewer), o.Timestamp, textutil.SafeField(o.Reason),
		func() string {
			if o.EvidenceRef != "" {
				return " (evidence: `" + o.EvidenceRef + "`)"
			}
			return ""
		}())
}
