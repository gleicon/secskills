package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/finding"
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
	Class          string `json:"class"` // positive-simple|positive-edge|negative|not-applicable
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
		// --- LLM intermediary (canary reflection + oracle drift) --------------
		{Name: "llm-canary", Class: "positive-simple", ExpectDetector: "llm.canary-reflection@1", ExpectSeverity: "MEDIUM",
			Title: "LLM endpoint reflects planted canary token", ProbeKind: "manual", Host: "https://h8.example.com", ProbeURL: "https://h8.example.com/v1/chat/completions", Validation: "behavior-confirmed"},
		{Name: "llm-drift", Class: "positive-simple", ExpectDetector: "llm.response-drift@1", ExpectSeverity: "LOW",
			Title: "LLM deterministic-oracle drift across warm-up rounds", ProbeKind: "manual", Host: "https://h8.example.com", ProbeURL: "https://h8.example.com/v1/chat/completions", Validation: "behavior-confirmed"},
		{Name: "llm-sysleak", Class: "positive-simple", ExpectDetector: "llm.system-prompt-leak@1", ExpectSeverity: "MEDIUM",
			Title: "LLM chatbot discloses system prompt", ProbeKind: "manual", Host: "https://h8.example.com", ProbeURL: "https://h8.example.com/v1/chat/completions", Validation: "behavior-confirmed"},
		// --- unauth exposure: metrics severity by content ------------------
		{Name: "metrics-generic", Class: "negative", ExpectDetector: "http.prometheus.public-metrics@1", ExpectSeverity: "LOW",
			Title: "Prometheus metrics exposed unauthenticated (generic runtime metrics only)", ProbeKind: "body-contains", Host: "https://h5.example.com", ProbeURL: "https://h5.example.com/metrics", Validation: "behavior-confirmed",
			ObservedEvidence: "Observed sensitive classes (unauthenticated /metrics sample):\n  [ ] internal hostname\n  [ ] namespace / topology (k8s)\n  [ ] credential-like pattern (unvalidated)\n"},
		{Name: "metrics-topology", Class: "positive-simple", ExpectDetector: "http.prometheus.public-metrics@1", ExpectSeverity: "MEDIUM",
			Title: "Prometheus metrics exposed unauthenticated", ProbeKind: "body-contains", Host: "https://h5.example.com", ProbeURL: "https://h5.example.com/metrics", Validation: "behavior-confirmed",
			ObservedEvidence: "Observed sensitive classes (unauthenticated /metrics sample):\n  [x] internal hostname\n  [x] namespace / topology (k8s)\n  [ ] credential-like pattern (unvalidated)\n"},
		{Name: "metrics-credential-pattern", Class: "positive-edge", ExpectDetector: "http.prometheus.public-metrics@1", ExpectSeverity: "MEDIUM",
			Title: "Prometheus metrics exposed unauthenticated", ProbeKind: "body-contains", Host: "https://h5.example.com", ProbeURL: "https://h5.example.com/metrics", Validation: "behavior-confirmed",
			ObservedEvidence: "Observed sensitive classes (unauthenticated /metrics sample):\n  [x] internal hostname\n  [x] credential-like pattern (unvalidated)\n"},
		{Name: "metrics-credential-confirmed", Class: "positive-edge", ExpectDetector: "http.prometheus.public-metrics@1", ExpectSeverity: "HIGH",
			Title: "Prometheus metrics exposed unauthenticated", ProbeKind: "body-contains", Host: "https://h5.example.com", ProbeURL: "https://h5.example.com/metrics", Validation: "behavior-confirmed",
			ObservedEvidence: "Observed sensitive classes (unauthenticated /metrics sample):\n  [x] internal hostname\n  [x] credential value confirmed\n"},
		// --- exposure path --------------------------------------------------
		{Name: "git-exposed", Class: "positive-simple", ExpectDetector: "http.exposure-path@1", ExpectSeverity: "MEDIUM",
			Title: "Exposed path: /.git/config", ProbeKind: "status", Host: "https://h6.example.com", ProbeURL: "https://h6.example.com/.git/config", Validation: "behavior-confirmed"},
		// --- component lead -------------------------------------------------
		{Name: "component-lead", Class: "positive-simple", ExpectDetector: "component.banner-osv-correlation@1", ExpectSeverity: "LOW",
			Title: "Potentially vulnerable outdated component: nginx 1.18.0", Host: "https://h7.example.com", Validation: "version-inferred"},
	}
}

// ConformanceScore is one detector family's tally on the offline corpus.
type ConformanceScore struct {
	TP, FP, FN int `json:"-"`
}

// RunConformance scores the corpus against the live classification pipeline.
func RunConformance() (map[string]*ConformanceScore, []string) {
	scores := map[string]*ConformanceScore{}
	get := func(fam string) *ConformanceScore {
		if scores[fam] == nil {
			scores[fam] = &ConformanceScore{}
		}
		return scores[fam]
	}
	var mismatches []string
	for _, fx := range corpus() {
		f := &finding.Finding{Title: fx.Title, ProbeKind: fx.ProbeKind, ProbeArg: fx.ProbeArg,
			Host: fx.Host, ProbeURL: fx.ProbeURL, Validation: fx.Validation, ObservedEvidence: fx.ObservedEvidence}
		finding.EnsureEvidenceFields(f)
		gotDet := finding.DetectorIDFor(f)
		gotSev, _ := finding.AssessSeverity(f)

		fam := fx.ExpectDetector
		if fam == "" {
			fam = gotDet
		}
		s := get(fam)
		detOK := gotDet == fx.ExpectDetector
		sevOK := strings.EqualFold(gotSev, fx.ExpectSeverity)
		if detOK && sevOK {
			s.TP++
		} else {
			s.FP++
			s.FN++
			mismatches = append(mismatches, fmt.Sprintf("%s: detector got=%s want=%s | severity got=%s want=%s",
				fx.Name, gotDet, fx.ExpectDetector, gotSev, fx.ExpectSeverity))
		}
	}
	return scores, mismatches
}

// Precision is TP/(TP+FP), or 1 with no positives.
func Precision(s *ConformanceScore) float64 {
	if s.TP+s.FP == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FP)
}

// Recall is TP/(TP+FN), or 1 with nothing to find.
func Recall(s *ConformanceScore) float64 {
	if s.TP+s.FN == 0 {
		return 1
	}
	return float64(s.TP) / float64(s.TP+s.FN)
}

// RenderScorecard renders the detector quality scorecard for the report.
func RenderScorecard() string {
	scores, _ := RunConformance()
	fams := make([]string, 0, len(scores))
	for k := range scores {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	var b strings.Builder
	b.WriteString("| Detector family | TP | FP | FN | Precision | Recall |\n|---|--:|--:|--:|--:|--:|\n")
	for _, f := range fams {
		s := scores[f]
		b.WriteString(fmt.Sprintf("| `%s` | %d | %d | %d | %.0f%% | %.0f%% |\n", f, s.TP, s.FP, s.FN, Precision(s)*100, Recall(s)*100))
	}
	b.WriteString("\n_Measured against the committed offline regression corpus (`secskills conformance`). Every fixed report inconsistency adds a fixture, so it cannot regress silently._")
	return b.String()
}
