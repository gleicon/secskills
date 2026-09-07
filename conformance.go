package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Items 1 & 2 — Detector regression corpus + conformance suite.
// A labeled corpus of known-vulnerable and known-safe cases exercises each
// detector's decision logic offline. cmdConformance scores TP/FP/FN and prints
// precision/recall per detector family, and a regression test (conformance_test.go)
// fails the build if measured quality drops below the committed thresholds.

// Fixture is one labeled case. It drives the pure classification pipeline
// (findingType + assessSeverity + evidence-state) without touching the network.
type Fixture struct {
	Name           string `json:"name"`
	Class          string `json:"class"`    // positive-simple|positive-edge|negative|not-applicable
	ExpectDetector string `json:"expect_detector"`
	ExpectSeverity string `json:"expect_severity"`
	// synthetic finding inputs
	Title            string `json:"title"`
	ProbeKind        string `json:"probe_kind"`
	ProbeArg         string `json:"probe_arg"`
	Host             string `json:"host"`
	ProbeURL         string `json:"probe_url"`
	Validation       string `json:"validation"`
	ObservedEvidence string `json:"observed_evidence"`
	// negative cases carry ExpectDetector "" (no finding of the family expected)
}

// corpus returns the committed regression corpus. Extend it whenever a report
// inconsistency is found (regression-first), so the same bug cannot return.
func corpus() []Fixture {
	return []Fixture{
		// --- TLS deprecated -------------------------------------------------
		{Name: "tls10-accepted", Class: "positive-simple", ExpectDetector: "tls.deprecated-protocol@1", ExpectSeverity: "MEDIUM",
			Title: "Deprecated TLS 1.0 accepted (RFC 8996)", ProbeKind: "tls-weak", ProbeArg: "1.0", Host: "https://h1.example.com", ProbeURL: "h1.example.com:443", Validation: "behavior-confirmed"},
		{Name: "weak-tls-3des", Class: "positive-edge", ExpectDetector: "tls.deprecated-protocol@1", ExpectSeverity: "MEDIUM",
			Title: "Weak TLS configuration (ciphers: 3DES)", ProbeKind: "tls-weak", ProbeArg: "1.0", Host: "https://h2.example.com", ProbeURL: "h2.example.com:443", Validation: "behavior-confirmed",
			ObservedEvidence: "TLSv1.0: accepted\nweak ciphers accepted: 3DES\n"},
		// --- security headers ----------------------------------------------
		{Name: "hsts-missing", Class: "positive-simple", ExpectDetector: "http.header.hsts-missing@1", ExpectSeverity: "LOW",
			Title: "Missing HSTS (Strict-Transport-Security)", ProbeKind: "header-missing", ProbeArg: "Strict-Transport-Security", Host: "https://h3.example.com", ProbeURL: "https://h3.example.com/", Validation: "passive"},
		{Name: "csp-missing", Class: "positive-simple", ExpectDetector: "http.header.csp-missing@1", ExpectSeverity: "LOW",
			Title: "Missing Content-Security-Policy", ProbeKind: "header-missing", ProbeArg: "Content-Security-Policy", Host: "https://h3.example.com", ProbeURL: "https://h3.example.com/", Validation: "passive"},
		{Name: "nosniff-missing", Class: "positive-simple", ExpectDetector: "http.header.nosniff-missing@1", ExpectSeverity: "LOW",
			Title: "Missing X-Content-Type-Options (nosniff)", ProbeKind: "header-missing", ProbeArg: "X-Content-Type-Options", Host: "https://h3.example.com", ProbeURL: "https://h3.example.com/", Validation: "passive"},
		// --- CORS -----------------------------------------------------------
		{Name: "cors-wildcard-no-creds", Class: "negative", ExpectDetector: "http.cors@1", ExpectSeverity: "INFORMATIONAL",
			Title: "Permissive CORS header (ACAO:* without credentials)", ProbeKind: "header-missing", ProbeArg: "access-control-allow-origin", Host: "https://h4.example.com", ProbeURL: "https://h4.example.com/", Validation: "passive"},
		{Name: "cors-creds", Class: "positive-simple", ExpectDetector: "http.cors@1", ExpectSeverity: "MEDIUM",
			Title: "Permissive CORS with credentials (ACAO:* + ACAC:true)", ProbeKind: "header-missing", ProbeArg: "access-control-allow-origin", Host: "https://h4.example.com", ProbeURL: "https://h4.example.com/", Validation: "passive"},
		// --- unauth exposure: metrics severity by content ------------------
		{Name: "metrics-generic", Class: "negative", ExpectDetector: "http.prometheus.public-metrics@1", ExpectSeverity: "LOW",
			Title: "Prometheus metrics exposed unauthenticated (generic runtime metrics only)", ProbeKind: "body-contains", Host: "https://h5.example.com", ProbeURL: "https://h5.example.com/metrics", Validation: "behavior-confirmed",
			ObservedEvidence: "Observed sensitive classes (unauthenticated /metrics sample):\n  [ ] internal hostname\n  [ ] namespace / topology (k8s)\n  [ ] credential-like pattern (unvalidated)\n"},
		{Name: "metrics-topology", Class: "positive-simple", ExpectDetector: "http.prometheus.public-metrics@1", ExpectSeverity: "MEDIUM",
			Title: "Prometheus metrics exposed unauthenticated", ProbeKind: "body-contains", Host: "https://h5.example.com", ProbeURL: "https://h5.example.com/metrics", Validation: "behavior-confirmed",
			ObservedEvidence: "Observed sensitive classes (unauthenticated /metrics sample):\n  [x] internal hostname\n  [x] namespace / topology (k8s)\n  [ ] credential-like pattern (unvalidated)\n"},
		{Name: "metrics-credentials", Class: "positive-edge", ExpectDetector: "http.prometheus.public-metrics@1", ExpectSeverity: "HIGH",
			Title: "Prometheus metrics exposed unauthenticated", ProbeKind: "body-contains", Host: "https://h5.example.com", ProbeURL: "https://h5.example.com/metrics", Validation: "behavior-confirmed",
			ObservedEvidence: "Observed sensitive classes (unauthenticated /metrics sample):\n  [x] internal hostname\n  [x] credential-like pattern (unvalidated)\n"},
		// --- exposure path --------------------------------------------------
		{Name: "git-exposed", Class: "positive-simple", ExpectDetector: "http.exposure-path@1", ExpectSeverity: "MEDIUM",
			Title: "Exposed path: /.git/config", ProbeKind: "status", Host: "https://h6.example.com", ProbeURL: "https://h6.example.com/.git/config", Validation: "behavior-confirmed"},
		// --- component lead -------------------------------------------------
		{Name: "component-lead", Class: "positive-simple", ExpectDetector: "component.banner-osv-correlation@1", ExpectSeverity: "LOW",
			Title: "Potentially vulnerable outdated component: nginx 1.18.0", Host: "https://h7.example.com", Validation: "version-inferred"},
	}
}

type score struct{ tp, fp, fn int }

// runConformance scores the corpus against the live classification pipeline.
func runConformance() (map[string]*score, []string) {
	scores := map[string]*score{}
	get := func(fam string) *score {
		if scores[fam] == nil {
			scores[fam] = &score{}
		}
		return scores[fam]
	}
	var mismatches []string
	for _, fx := range corpus() {
		f := &Finding{Title: fx.Title, ProbeKind: fx.ProbeKind, ProbeArg: fx.ProbeArg,
			Host: fx.Host, ProbeURL: fx.ProbeURL, Validation: fx.Validation, ObservedEvidence: fx.ObservedEvidence}
		ensureEvidenceFields(f)
		gotDet := detectorIDFor(f)
		gotSev, _ := assessSeverity(f)

		fam := fx.ExpectDetector
		if fam == "" {
			fam = gotDet
		}
		s := get(fam)
		detOK := gotDet == fx.ExpectDetector
		sevOK := strings.EqualFold(gotSev, fx.ExpectSeverity)
		if detOK && sevOK {
			s.tp++
		} else {
			s.fp++
			s.fn++
			mismatches = append(mismatches, fmt.Sprintf("%s: detector got=%s want=%s | severity got=%s want=%s",
				fx.Name, gotDet, fx.ExpectDetector, gotSev, fx.ExpectSeverity))
		}
	}
	return scores, mismatches
}

func precision(s *score) float64 {
	if s.tp+s.fp == 0 {
		return 1
	}
	return float64(s.tp) / float64(s.tp+s.fp)
}
func recall(s *score) float64 {
	if s.tp+s.fn == 0 {
		return 1
	}
	return float64(s.tp) / float64(s.tp+s.fn)
}

// cmdConformance runs the corpus and prints the detector quality scorecard.
func cmdConformance(args []string) error {
	fs := flag.NewFlagSet("conformance", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit machine-readable scorecard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scores, mismatches := runConformance()
	fams := make([]string, 0, len(scores))
	for k := range scores {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	if *asJSON {
		out := map[string]any{}
		for _, f := range fams {
			out[f] = map[string]any{"tp": scores[f].tp, "fp": scores[f].fp, "fn": scores[f].fn,
				"precision": precision(scores[f]), "recall": recall(scores[f])}
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Println("Detector quality scorecard (offline regression corpus)")
	fmt.Println("| Detector family | TP | FP | FN | Precision | Recall |")
	fmt.Println("|-----------------|---:|---:|---:|----------:|-------:|")
	for _, f := range fams {
		s := scores[f]
		fmt.Printf("| %s | %d | %d | %d | %.0f%% | %.0f%% |\n", f, s.tp, s.fp, s.fn, precision(s)*100, recall(s)*100)
	}
	if len(mismatches) > 0 {
		fmt.Println("\nMismatches:")
		for _, m := range mismatches {
			fmt.Println("  - " + m)
		}
		os.Exit(1)
	}
	return nil
}

// renderScorecard renders the detector quality scorecard for the report.
func renderScorecard() string {
	scores, _ := runConformance()
	fams := make([]string, 0, len(scores))
	for k := range scores {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	var b strings.Builder
	b.WriteString("| Detector family | TP | FP | FN | Precision | Recall |\n|---|--:|--:|--:|--:|--:|\n")
	for _, f := range fams {
		s := scores[f]
		b.WriteString(fmt.Sprintf("| `%s` | %d | %d | %d | %.0f%% | %.0f%% |\n", f, s.tp, s.fp, s.fn, precision(s)*100, recall(s)*100))
	}
	b.WriteString("\n_Measured against the committed offline regression corpus (`secskills conformance`). Every fixed report inconsistency adds a fixture, so it cannot regress silently._")
	return b.String()
}
