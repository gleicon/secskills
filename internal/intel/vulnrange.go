package intel

import "strings"

// Version-range matching for userland products (spec FR-4, the non-kernel path).
// A VulnRange is an affected-version constraint for one CVE against one CPE
// product, as published by NVD/OSV. Matching an observed (product, version)
// against these ranges is deterministic and model-free.
//
// Honesty invariant (consistent with the kernel matcher): a version in an
// affected range is a CANDIDATE at version-inferred confidence, never a
// confirmed finding. Distro backports routinely patch a CVE while leaving the
// upstream version string unchanged (e.g. Apache 2.4.52 on RHEL), so PatchState
// stays "unknown" — the candidate must be confirmed against the backport.

// VulnRange is one CVE's affected-version window for a CPE vendor:product.
type VulnRange struct {
	CVE                   string  `json:"cve"`
	Vendor                string  `json:"vendor"`
	Product               string  `json:"product"`
	VersionStartIncluding string  `json:"version_start_including,omitempty"`
	VersionStartExcluding string  `json:"version_start_excluding,omitempty"`
	VersionEndIncluding   string  `json:"version_end_including,omitempty"`
	VersionEndExcluding   string  `json:"version_end_excluding,omitempty"`
	CVSS                  float64 `json:"cvss,omitempty"`
	KEV                   bool    `json:"kev,omitempty"`
}

// vercmp compares two version strings by their numeric tokens, left to right.
// Mixed separators (dots, dashes, the OpenSSH "p" patch marker) are all treated
// as separators, so "9.6p1" -> [9,6,1]. When one is a prefix of the other the
// longer compares greater ("9.6p1" > "9.6"). Returns -1, 0, or 1.
func vercmp(a, b string) int {
	ta, tb := numericTokens(a), numericTokens(b)
	for i := 0; i < len(ta) && i < len(tb); i++ {
		if ta[i] != tb[i] {
			if ta[i] < tb[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ta) < len(tb):
		return -1
	case len(ta) > len(tb):
		return 1
	}
	return 0
}

// InRange reports whether ver falls inside the range's bounds. An unbounded side
// is open; a range with no bounds at all matches every version (NVD publishes
// such "all versions affected" nodes).
func (r VulnRange) InRange(ver string) bool {
	if ver == "" {
		return false
	}
	if r.VersionStartIncluding != "" && vercmp(ver, r.VersionStartIncluding) < 0 {
		return false
	}
	if r.VersionStartExcluding != "" && vercmp(ver, r.VersionStartExcluding) <= 0 {
		return false
	}
	if r.VersionEndIncluding != "" && vercmp(ver, r.VersionEndIncluding) > 0 {
		return false
	}
	if r.VersionEndExcluding != "" && vercmp(ver, r.VersionEndExcluding) >= 0 {
		return false
	}
	return true
}

// MatchProduct returns one candidate per CVE whose range covers (product,
// version). product is matched case-insensitively against each range's Product.
// Every candidate is L1/version-inferred with PatchState "unknown": a backport
// may have patched the CVE behind an unchanged version string.
func MatchProduct(ip, product, version string, ranges []VulnRange) []Candidate {
	if product == "" || version == "" {
		return nil
	}
	pl := strings.ToLower(product)
	var out []Candidate
	seen := map[string]bool{}
	for _, r := range ranges {
		if seen[r.CVE] || !productMatch(pl, r.Product) {
			continue
		}
		if !r.InRange(version) {
			continue
		}
		seen[r.CVE] = true
		c := Candidate{
			AssetIP:    ip,
			CVE:        r.CVE,
			Tier:       "L1",
			Confidence: "medium",
			PatchState: "unknown",
			Claim: product + " " + version + " is within the affected range of " + r.CVE +
				" (" + r.summarize() + ") — version-inferred, confirm against distro backports",
			UrgentFeed: r.KEV, // only KEV-listed version matches escalate from a banner
			ScoreTerms: map[string]float64{"confidence": 0.6, "cvss": r.CVSS},
		}
		out = append(out, c)
	}
	return out
}

// productMatch reports whether an observed product name corresponds to a range's
// CPE product token (nginx==nginx, "http_server" for Apache, etc.).
func productMatch(observedLower, rangeProduct string) bool {
	rp := strings.ToLower(rangeProduct)
	if rp == "" {
		return false
	}
	if rp == observedLower || strings.Contains(observedLower, rp) || strings.Contains(rp, observedLower) {
		return true
	}
	// Apache's CPE product is "http_server"; its banner says "Apache".
	if rp == "http_server" && strings.Contains(observedLower, "apache") {
		return true
	}
	return false
}

func (r VulnRange) summarize() string {
	var p []string
	if r.VersionStartIncluding != "" {
		p = append(p, ">= "+r.VersionStartIncluding)
	}
	if r.VersionStartExcluding != "" {
		p = append(p, "> "+r.VersionStartExcluding)
	}
	if r.VersionEndIncluding != "" {
		p = append(p, "<= "+r.VersionEndIncluding)
	}
	if r.VersionEndExcluding != "" {
		p = append(p, "< "+r.VersionEndExcluding)
	}
	if len(p) == 0 {
		return "all versions"
	}
	return strings.Join(p, ", ")
}
