package main

import (
	"strings"
	"fmt"
	"math"
)

// A real (indicative) CVSS v3.1 base vector + score per finding, computed with the
// FIRST.org base formula — replacing the "severity band" the report used to print.
// Metrics are chosen per finding class/evidence; the score is computed, not a
// range. Where the metric assumptions are approximate (e.g. version-inferred
// component CVEs whose per-CVE vectors vary), the vector is labelled indicative.

type cvssMetrics struct{ AV, AC, PR, UI, C, I, A string }

func metricsFor(f *Finding) cvssMetrics {
	m := cvssMetrics{AV: "N", AC: "L", PR: "N", UI: "N", C: "N", I: "N", A: "N"}
	switch f.KBClass {
	case "config-exposure":
		m.C = "L"
		if f.Severity == "HIGH" { // e.g. metrics leaking internal detail
			m.C = "H"
		}
		if f.Severity == "INFORMATIONAL" {
			m.C = "N"
		}
	case "crypto-secrets":
		m.AC, m.C, m.I = "H", "L", "L" // on-path attacker required
	case "components-supply-chain":
		m.C = "L" // indicative; real per-CVE vectors vary
	case "access-control":
		m.PR, m.C = "L", "H"
	case "auth-session":
		m.C = "H"
	case "injection":
		m.C, m.I, m.A = "H", "H", "H"
	case "ssrf-xxe":
		m.C = "H"
	case "logging-monitoring":
		m.C = "L"
	default:
		m.C = "L"
	}
	return m
}

func cvssVector(f *Finding) (string, float64) {
	m := metricsFor(f)
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m.AV]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m.AC]
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m.PR]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m.UI]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	iss := 1 - (1-cia[m.C])*(1-cia[m.I])*(1-cia[m.A])
	impact := 6.42 * iss
	expl := 8.22 * av * ac * pr * ui
	score := 0.0
	if impact > 0 {
		score = roundUp(math.Min(impact+expl, 10))
	}
	vec := fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:U/C:%s/I:%s/A:%s",
		m.AV, m.AC, m.PR, m.UI, m.C, m.I, m.A)
	return vec, score
}

// roundUp implements the CVSS v3.1 "roundup" (to one decimal, always up).
func roundUp(x float64) float64 {
	return math.Ceil(x*10) / 10
}

// cvssString renders "CVSS:3.1/... = 5.3" with an indicative note for version-inferred.
func cvssString(f *Finding) string {
	if cvssNotApplicable(f) {
		return "N/A (informational / negative evidence — not a vulnerability)"
	}
	vec, score := cvssVector(f)
	s := fmt.Sprintf("%s = %.1f", vec, score)
	if f.Validation == "version-inferred" || f.KBClass == "components-supply-chain" {
		s += " (indicative — per-CVE vectors vary; validate)"
	}
	return s
}



// cvssScoreStr returns the exact CVSS v3.1 base score as a string (deterministic;
// no bands/ranges — if we know the vector we show the number).
func cvssScoreStr(f *Finding) string {
	if cvssNotApplicable(f) {
		return "N/A"
	}
	_, score := cvssVector(f)
	return fmt.Sprintf("%.1f", score)
}

// cvssNotApplicable reports whether CVSS should be N/A: CVSS describes a
// vulnerability, so informational findings and negative evidence (a control that
// held, e.g. "resisted N bypass classes") have no CVSS.
func cvssNotApplicable(f *Finding) bool {
	if strings.EqualFold(f.Severity, "INFORMATIONAL") {
		return true
	}
	switch detectorOf(f) {
	case "http.authz-boundary@1":
		return true
	}
	return false
}
