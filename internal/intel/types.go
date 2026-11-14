// Package intel is the deterministic vulnerability matcher (spec FR-4): it joins
// NVD version ranges with banner-observed product/version into tier-labelled
// candidates. No model is on this path — "why is this a candidate, and at what
// confidence" is answerable from data.
//
// The honesty invariant (spec D-3): external evidence is version-inferred (L1)
// and never claims a host is patched or vulnerable.
package intel

// Candidate is a matcher output: an asset × CVE with the confidence tier that
// produced it, the claim it licenses, and the named score terms.
type Candidate struct {
	AssetIP     string             `json:"asset_ip"`
	CVE         string             `json:"cve"`
	Tier        string             `json:"tier"`        // L0 | L1 | L2 | L3
	Confidence  string             `json:"confidence"`  // low | medium | high | verified
	PatchState  string             `json:"patch_state"` // unknown | patched | unpatched
	Claim       string             `json:"claim"`
	Remediation string             `json:"remediation"`
	UrgentFeed  bool               `json:"urgent_feed"`
	Score       float64            `json:"score"`
	ScoreTerms  map[string]float64 `json:"score_terms"`
}
