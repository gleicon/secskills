package main

import (
	"fmt"
	"strings"
)

// Adversarial Control Ledger — denominators for the active adversarial modules,
// so "Completed (adversarial-readonly)" is scientifically meaningful. Derived
// from the in-scope live-host population and the findings each module produced.
func renderAdversarialLedger(findings []Finding, live []LiveHost, wd string, apex string, labels []string) string {
	if !readProfile(wd).adversarial() {
		return "_Adversarial modules did not run (profile is not adversarial-readonly)._"
	}
	if m := renderMeasuredLedger(wd); m != "" {
		return m
	}
	// count reachable live hosts (per-host module denominator)
	reachable := 0
	protected := 0
	for _, h := range live {
		if h.Status > 0 {
			reachable++
		}
		if h.Status == 401 || h.Status == 403 {
			protected++
		}
	}
	pos := map[string]int{}
	inc := map[string]int{}
	for i := range findings {
		f := &findings[i]
		d := detectorOf(f)
		if isInconclusive(f) {
			inc[d]++
			continue
		}
		pos[d]++
	}
	oastNote := "OAST not configured (SECSKILLS_OAST_DOMAIN unset) — blind SSRF validation unavailable this run"
	if newOAST().available() {
		oastNote = "OAST configured"
	}
	buckets := len(bucketCandidates(apex, labels))

	type row struct {
		module, detector string
		candidates       int
		positive         int
		note             string
	}
	rows := []row{
		{"Trusted-header / auth-bypass", "http.authz-bypass@1 / edge.header-acl-bypass@1", protected, pos["http.authz-bypass@1"] + pos["edge.header-acl-bypass@1"], fmt.Sprintf("negative evidence: %d boundaries resisted", pos["http.authz-boundary@1"])},
		{"Open redirect", "http.open-redirect@1", reachable, pos["http.open-redirect@1"], "GET-only redirect-to-canary"},
		{"SSTI (arithmetic)", "ssti.arithmetic@1", reachable, pos["ssti.arithmetic@1"], "rare-operand differential"},
		{"SSRF (OAST)", "http.ssrf@1", reachable, pos["http.ssrf@1"], oastNote},
		{"OIDC / identity surface", "identity.oidc-surface@1", reachable, pos["identity.oidc-surface@1"], "well-known discovery"},
		{"API schema / verbose error", "api.schema-exposure@1 / api.verbose-error@1", reachable, pos["api.schema-exposure@1"] + pos["api.verbose-error@1"], "OpenAPI/Swagger/GraphQL + error leakage"},
		{"Object-storage enumeration", "storage.public-bucket@1", buckets, pos["storage.public-bucket@1"], "S3/GCS/Azure candidate buckets"},
		{"Origin looking-glass", "edge.origin-exposure@1", 0, pos["edge.origin-exposure@1"], "Shodan-gated (favicon/cert pivots)"},
	}
	var b strings.Builder
	b.WriteString("| Adversarial module | Candidates | Positive | Inconclusive | Note |\n|---|--:|--:|--:|---|\n")
	for _, r := range rows {
		incn := inc[strings.SplitN(r.detector, " / ", 2)[0]]
		cand := r.candidates
		candStr := itoa(cand)
		if cand == 0 {
			candStr = "—"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %s |\n", r.module, candStr, r.positive, incn, r.note))
	}
	b.WriteString("\n_Candidates = the population each module was applied to (reachable live hosts for per-host modules; protected 401/403 endpoints for bypass; candidate bucket names for object storage; Shodan-derived IPs for the origin looking-glass). Positive = confirmed findings; a zero positive with a non-zero candidate count is a real negative result, not \"not tested\"._")
	return b.String()
}
