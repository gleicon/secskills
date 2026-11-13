package exposure

// KEVCVESet returns the set of CVE ids currently in the cached KEV catalog.
func KEVCVESet() map[string]bool {
	s := map[string]bool{}
	for _, e := range LoadKEVForEnrich() {
		s[e.CVE] = true
	}
	return s
}

// CandidateScore ranks a version-inferred candidate (spec §10, reduced form for
// the external tier): confidence 0.6, weighting KEV most, then EPSS, then CVSS.
// All terms are stored on the candidate so the rank is reproducible.
func CandidateScore(kevTerm, epss, cvss float64) float64 {
	return 0.6 * (0.5*kevTerm + 0.3*epss + 0.2*cvss/10.0)
}
