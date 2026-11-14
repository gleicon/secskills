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
