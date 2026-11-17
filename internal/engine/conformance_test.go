package engine

import (
	"testing"
)

// TestConformanceThresholds is the detector regression gate: the committed
// corpus must classify at or above these precision/recall floors, and produce
// no mismatches. A detector change that regresses quality fails the build.
func TestConformanceThresholds(t *testing.T) {
	scores, mismatches := RunConformance()
	if len(mismatches) != 0 {
		for _, m := range mismatches {
			t.Errorf("conformance mismatch: %s", m)
		}
	}
	for fam, s := range scores {
		if p := Precision(s); p < 0.90 {
			t.Errorf("%s precision %.2f below floor 0.90", fam, p)
		}
		if r := Recall(s); r < 0.90 {
			t.Errorf("%s recall %.2f below floor 0.90", fam, r)
		}
	}
}
