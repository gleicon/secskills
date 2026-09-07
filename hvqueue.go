package main

import (
	"fmt"
	"sort"
	"strings"
)

// Human-validation queue. A strong adversarial engine knows what it cannot safely
// prove. Instead of a flat "manual validation recommended", rank manual candidates
// by exploitability x asset-sensitivity x chaining-potential x evidence-quality
// and surface a short human red-team queue.
type hvItem struct {
	f     *Finding
	score float64
}

func hvScore(f *Finding, capCount map[string]int) float64 {
	// exploitability: confirmed/exploitable weighs more; inconclusive still queued
	exploit := map[string]float64{"exploited": 1.0, "behavior-confirmed": 0.8, "config-inferred": 0.5, "version-inferred": 0.4, "passive": 0.3, "inconclusive": 0.6}[f.Validation]
	if exploit == 0 {
		exploit = 0.3
	}
	// asset sensitivity from finding type
	sens := 0.4
	switch findingType(f) {
	case "metrics-exposed", "exposure-path":
		sens = 0.8
	case "cors":
		sens = 0.6
	}
	switch detectorOf(f) {
	case "storage.public-bucket@1", "ssti.arithmetic@1", "http.ssrf@1", "http.authz-bypass@1", "http.open-redirect@1":
		sens = 0.95
	case "identity.oidc-surface@1", "api.schema-exposure@1":
		sens = 0.7
	}
	// chaining potential: how many other findings share this finding's capabilities
	chain := 0.0
	caps := f.Capabilities
	if len(caps) == 0 {
		caps = capabilitiesFor(f)
	}
	for _, c := range caps {
		chain += float64(capCount[c])
	}
	chainNorm := chain / (chain + 4.0) // 0..1 saturating
	// evidence quality
	evq := 0.4
	if len(f.EvidenceRefs) > 0 {
		evq = 0.8
	}
	return exploit*sens*(0.5+0.5*chainNorm)*(0.5+0.5*evq) * 10
}

// renderHumanQueue returns the top manual-validation candidates.
func renderHumanQueue(findings []Finding) string {
	capCount := map[string]int{}
	for i := range findings {
		caps := findings[i].Capabilities
		if len(caps) == 0 {
			caps = capabilitiesFor(&findings[i])
		}
		for _, c := range caps {
			capCount[c]++
		}
	}
	var items []hvItem
	for i := range findings {
		f := &findings[i]
		// queue only things a human should look at (skip clean negative evidence)
		if f.Severity == "INFORMATIONAL" && f.Validation == "behavior-confirmed" && !isInconclusive(f) {
			continue
		}
		items = append(items, hvItem{f: f, score: hvScore(f, capCount)})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].score > items[j].score })
	if len(items) > 5 {
		items = items[:5]
	}
	if len(items) == 0 {
		return "_No high-value manual-validation candidates._"
	}
	var b strings.Builder
	b.WriteString("| Rank | Score | Finding | Asset | State | Why it needs a human |\n|---|--:|---|---|---|---|\n")
	for i, it := range items {
		fmt.Fprintf(&b, "| %d | %.1f | %s | %s | %s | %s |\n", i+1, it.score, safeField(displayTitle(it.f)), safeField(it.f.Host), orDash(it.f.State), hvReason(it.f))
	}
	b.WriteString("\n_Ranked by exploitability x asset-sensitivity x chaining-potential x evidence-quality. Automation does the broad work; a specialist should spend time here first._")
	return b.String()
}

func hvReason(f *Finding) string {
	if isInconclusive(f) {
		return "validation blocked — confirm from an unblocked vantage"
	}
	switch detectorOf(f) {
	case "ssti.arithmetic@1":
		return "arithmetic evaluated — attempt safe RCE confirmation"
	case "http.ssrf@1":
		return "OAST interaction — map reachable internal targets"
	case "storage.public-bucket@1":
		return "enumerate objects for sensitive content"
	case "identity.oidc-surface@1":
		return "test redirect-URI / token config"
	case "metrics-exposed":
		return "assess pivot intelligence for reachable internal services"
	}
	return "manual validation of impact"
}
