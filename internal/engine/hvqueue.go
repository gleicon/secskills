package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/textutil"
)

// Human-validation queue. A strong adversarial engine knows what it cannot safely
// prove. Instead of a flat "manual validation recommended", rank manual candidates
// by exploitability x asset-sensitivity x chaining-potential x evidence-quality
// and surface a short human red-team queue.
type hvItem struct {
	f     *finding.Finding
	score float64
}

func hvScore(f *finding.Finding, capCount map[string]int) float64 {
	// exploitability: confirmed/exploitable weighs more; inconclusive still queued
	exploit := map[string]float64{"exploited": 1.0, "behavior-confirmed": 0.8, "config-inferred": 0.5, "version-inferred": 0.4, "passive": 0.3, "inconclusive": 0.6}[f.Validation]
	if exploit == 0 {
		exploit = 0.3
	}
	// asset sensitivity from finding type
	sens := 0.4
	switch finding.FindingType(f) {
	case "metrics-exposed", "exposure-path":
		sens = 0.8
	case "cors":
		sens = 0.6
	}
	switch finding.DetectorOf(f) {
	case "storage.public-bucket@1", "ssti.arithmetic@1", "http.ssrf@1", "http.authz-bypass@1", "http.open-redirect@1":
		sens = 0.95
	case "identity.oidc-surface@1", "api.schema-exposure@1":
		sens = 0.7
	}
	// chaining potential: how many other findings share this finding's capabilities
	chain := 0.0
	caps := f.Capabilities
	if len(caps) == 0 {
		caps = finding.CapabilitiesFor(f)
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
	// Expected Pivot Value: reward findings that grant capabilities opening NEW
	// attack surface (a red teamer's real objective), so a Prometheus disclosure
	// or an anonymous-read store outranks a deprecated-TLS observation.
	epv := 1.0
	capWeight := map[string]float64{
		finding.CapCredCandidate: 1.0, finding.CapAnonRead: 0.8, finding.CapInternalHosts: 0.7,
		finding.CapServerSideFetch: 0.9, finding.CapAuthBoundary: 0.6, finding.CapServiceVersion: 0.4,
		finding.CapTakeover: 0.7, finding.CapRedirect: 0.5,
	}
	for _, c := range caps {
		epv += capWeight[c]
	}
	// pure hardening deviations (no capability) get a low pivot value
	if len(caps) == 0 {
		epv = 0.5
	}
	return exploit * sens * (0.5 + 0.5*chainNorm) * (0.5 + 0.5*evq) * epv * 6
}

// RenderHumanQueue returns the top manual-validation candidates.
func RenderHumanQueue(findings []finding.Finding) string {
	capCount := map[string]int{}
	for i := range findings {
		caps := findings[i].Capabilities
		if len(caps) == 0 {
			caps = finding.CapabilitiesFor(&findings[i])
		}
		for _, c := range caps {
			capCount[c]++
		}
	}
	var items []hvItem
	for i := range findings {
		f := &findings[i]
		// queue only things a human should look at (skip clean negative evidence)
		if f.Severity == "INFORMATIONAL" && f.Validation == "behavior-confirmed" && !finding.IsInconclusive(f) {
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
	b.WriteString("| Rank | Expected Pivot Value | Finding | Asset | State | Why it needs a human |\n|---|--:|---|---|---|---|\n")
	for i, it := range items {
		fmt.Fprintf(&b, "| %d | %.1f | %s | %s | %s | %s |\n", i+1, it.score, textutil.SafeField(finding.DisplayTitle(it.f)), textutil.SafeField(it.f.Host), textutil.OrDash(it.f.State), hvReason(it.f))
	}
	b.WriteString("\n_Ranked by **Expected Pivot Value** = exploitability x asset-sensitivity x chaining x evidence-quality x capability-pivot-weight. Optimizes human attention for probability of reaching a NEW capability, not severity alone — so a disclosure that pivots outranks a deprecated-TLS observation._")
	return b.String()
}

func hvReason(f *finding.Finding) string {
	if finding.IsInconclusive(f) {
		return "validation blocked — confirm from an unblocked vantage"
	}
	switch finding.DetectorOf(f) {
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
