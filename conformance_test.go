package main

import "testing"

// TestConformanceThresholds is the detector regression gate: the committed
// corpus must classify at or above these precision/recall floors, and produce
// no mismatches. A detector change that regresses quality fails the build.
func TestConformanceThresholds(t *testing.T) {
	scores, mismatches := runConformance()
	if len(mismatches) != 0 {
		for _, m := range mismatches {
			t.Errorf("conformance mismatch: %s", m)
		}
	}
	for fam, s := range scores {
		if p := precision(s); p < 0.90 {
			t.Errorf("%s precision %.2f below floor 0.90", fam, p)
		}
		if r := recall(s); r < 0.90 {
			t.Errorf("%s recall %.2f below floor 0.90", fam, r)
		}
	}
}

// TestEvidenceStateMachineClosed asserts illegitimate transitions are rejected —
// e.g. a version-inferred lead cannot jump straight to EXPLOIT_VALIDATED, and a
// suppressed finding is terminal.
func TestEvidenceStateMachineClosed(t *testing.T) {
	if canTransition(StInferred, StExploitValidated) == false {
		t.Error("INFERRED should be able to reach EXPLOIT_VALIDATED via validation")
	}
	if canTransition(StDiscovered, StExploitValidated) {
		t.Error("DISCOVERED must not jump directly to EXPLOIT_VALIDATED")
	}
	if canTransition(StSuppressed, StObserved) {
		t.Error("SUPPRESSED must be terminal")
	}
	if canTransition(StNotApplicable, StConfirmed) {
		t.Error("NOT_APPLICABLE must be terminal")
	}
}
