package finding

import (
	"testing"

	"github.com/gleicon/secskills/internal/textutil"
)

func TestCVSSVector(t *testing.T) {
	// config-exposure LOW → C:L only → 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
	f := &Finding{KBClass: "config-exposure", Severity: "LOW"}
	vec, score := CVSSVector(f)
	if score != 5.3 {
		t.Errorf("config-exposure C:L score=%.1f want 5.3", score)
	}
	if !textutil.Contains([]string{vec}, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") {
		t.Errorf("unexpected vector %q", vec)
	}
	// injection (C:H/I:H/A:H) → 9.8
	if _, s := CVSSVector(&Finding{KBClass: "injection"}); s != 9.8 {
		t.Errorf("injection score=%.1f want 9.8", s)
	}
	// INFORMATIONAL hardening (C:N) → 0.0
	if _, s := CVSSVector(&Finding{KBClass: "config-exposure", Severity: "INFORMATIONAL"}); s != 0.0 {
		t.Errorf("informational score=%.1f want 0.0", s)
	}
}

func TestSetStatus(t *testing.T) {
	wd := t.TempDir()
	if err := AddFinding(wd, Finding{ID: "F-1", Title: "TLS 1.0 enabled", Host: "a.example:443", Severity: "MEDIUM", CVEs: []string{"CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := SetStatus(wd, "F-1", "accepted", "compensating control"); err != nil {
		t.Fatal(err)
	}
	f := LoadWorkFindings(wd)[0]
	if f.Status != "accepted" || len(f.CVEs) != 1 || f.Title != "TLS 1.0 enabled" {
		t.Fatalf("status change must keep the rest of the finding: %+v", f)
	}
	h := f.RetestHistory[len(f.RetestHistory)-1]
	if h["change"] != "open -> accepted" || h["retest_evidence"] != "compensating control" {
		t.Errorf("history entry %v", h)
	}
	if SetStatus(wd, "F-1", "mitigated", "") == nil {
		t.Error("mitigated must not be settable by hand")
	}
	if SetStatus(wd, "F-404", "accepted", "") == nil {
		t.Error("unknown id must fail")
	}
}

// Evidence state comes from how a finding was validated, never from severity:
// a version-inferred lead stays INFERRED even when its severity is raised.
func TestEvidenceStateFromValidation(t *testing.T) {
	wd := t.TempDir()
	f := Finding{ID: "L-1", Title: "Potentially vulnerable OpenSSH version 8.9p1 — manual validation required (1 CVEs)",
		Host: "203.0.113.10:22", Severity: "CRITICAL", Validation: "version-inferred", ObservedEvidence: "[x] CISA KEV: CVE-1"}
	if err := AddFinding(wd, f); err != nil {
		t.Fatal(err)
	}
	got := LoadWorkFindings(wd)[0]
	if got.State != string(StInferred) {
		t.Errorf("version-inferred finding state %q, want INFERRED", got.State)
	}
	if got.Severity == "CRITICAL" {
		t.Error("the rubric must not let a version-inferred lead stay CRITICAL")
	}
	for v, want := range map[string]EvidenceState{"exploited": StExploitValidated, "behavior-confirmed": StConfirmed,
		"inconclusive": StInconclusive, "": StObserved} {
		if s := stateForValidation(v); s != want {
			t.Errorf("stateForValidation(%q) = %s, want %s", v, s, want)
		}
	}
}
