package finding

import "strings"

// IsInconclusive reports whether a finding's validation did not establish the
// weakness (e.g. CAPTCHA/WAF interstitial, unreachable). Severity still reflects
// impact-if-true, but the language must not assert the weakness was confirmed.
func IsInconclusive(f *Finding) bool {
	return strings.EqualFold(f.Validation, "inconclusive") || strings.EqualFold(f.State, "INCONCLUSIVE")
}

// DisplayTitle renames an inconclusive finding so the title itself carries the
// epistemic state (survives hostile audit review), e.g.
// "Unauthenticated sensitive path" -> "Potential sensitive path exposure — validation inconclusive".
func DisplayTitle(f *Finding) string {
	t := f.Title
	if IsInconclusive(f) {
		low := strings.ToLower(t)
		if !strings.HasPrefix(low, "potential") && !strings.Contains(low, "inconclusive") {
			return "Potential: " + t + " — validation inconclusive"
		}
	}
	return t
}

// DisplayImpact returns impact text that does not over-claim for inconclusive
// findings. Confirmed findings keep their asset-specific impact.
func DisplayImpact(f *Finding) string {
	base := f.ImpactText
	if base == "" {
		base = impactFor(f.KBClass)
	}
	if IsInconclusive(f) {
		return "Potential impact only — the weakness was NOT confirmed this run (validation was blocked or the endpoint was unreachable). If the condition is real, the stated impact would apply. Severity reflects impact-if-true, not a validated exposure."
	}
	return base
}
