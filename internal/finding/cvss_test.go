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
