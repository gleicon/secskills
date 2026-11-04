package main

import "testing"

func TestCandidateScoreOrdering(t *testing.T) {
	// KEV must dominate EPSS must dominate CVSS.
	kevLow := candidateScore(1, 0.0, 0.0)   // KEV, no epss
	noKevHigh := candidateScore(0, 0.99, 9) // not KEV, high epss+cvss
	if kevLow <= noKevHigh {
		t.Errorf("a KEV match must outrank a non-KEV one: %.3f vs %.3f", kevLow, noKevHigh)
	}
	// Among non-KEV, higher EPSS wins.
	if candidateScore(0, 0.9, 5) <= candidateScore(0, 0.1, 5) {
		t.Error("higher EPSS must score higher")
	}
	// Among equal EPSS/KEV, higher CVSS wins.
	if candidateScore(0, 0.5, 9.8) <= candidateScore(0, 0.5, 4.0) {
		t.Error("higher CVSS must break the tie")
	}
}
