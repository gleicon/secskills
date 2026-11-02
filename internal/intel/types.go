// Package intel is the deterministic vulnerability matcher (spec FR-4): it joins
// a structured advisory, per-distro patch state, and the assets derived from
// probe observations into tier-labelled candidates. No model is on this path —
// "why is this a candidate, and at what confidence" is answerable from data.
//
// The honesty invariant (spec AC-3, D-3): external-only evidence (tiers L0/L1)
// never claims a kernel is vulnerable or patched. Only an agent-verified asset
// (L3) may state patch state. The matcher enforces this in code, not by
// convention.
package intel

// Advisory is a structured vulnerability record after extraction. For a kernel
// CVE the affected version lives in per-distro trackers (DistroState), not in a
// single semver range, because distros backport under their own versions.
type Advisory struct {
	ID        string  `json:"id"`
	Class     string  `json:"class"`   // kernel | service | web | config
	Package   string  `json:"package"` // linux, openssh, ...
	CVSS      float64 `json:"cvss"`
	KEV       bool    `json:"kev"`
	EPSS      float64 `json:"epss"`
	POCSignal int     `json:"poc_signal"` // e.g. count of public PoC repos
	Summary   string  `json:"summary"`

	// Preconditions that decide exposure for this class.
	RequiresReachableTCP bool `json:"requires_reachable_tcp"` // any listening IPv4 TCP port
	MPTCPMultiplier      bool `json:"mptcp_multiplier"`       // an MPTCP listener raises risk

	Remediation struct {
		Default    string `json:"default"`
		Mitigation string `json:"mitigation"`
	} `json:"remediation"`
}

// DistroEntry is the patch state for one (distro, release, package) — the unit
// the matcher trusts for kernel CVEs (spec D-9). Status is
// vulnerable|wip|testing|partial|fixed; FixedVersion is set only when fixed.
type DistroEntry struct {
	Distro       string `json:"distro"`
	Release      string `json:"release"`
	Package      string `json:"package"`
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version"`
	AsOf         string `json:"as_of"`
}

// DistroState is every tracked entry for one CVE.
type DistroState struct {
	CVE     string        `json:"cve"`
	Entries []DistroEntry `json:"entries"`
}

// find returns the entry for a (distro, release, package), or false.
func (d DistroState) find(distro, release, pkg string) (DistroEntry, bool) {
	for _, e := range d.Entries {
		if e.Distro == distro && e.Release == release && e.Package == pkg {
			return e, true
		}
	}
	return DistroEntry{}, false
}

// Asset is a host to evaluate, built from probe observations plus — when
// available — agent facts. The external fields (ReachableTCP, MPTCPCapable, OS)
// come from observation; Distro/Release/Kernel* come only from an agent (L3).
type Asset struct {
	IP            string `json:"ip"`
	OS            string `json:"os"` // linux | windows | "" (unknown)
	ReachableTCP  bool   `json:"reachable_tcp"`
	MPTCPCapable  bool   `json:"mptcp_capable"`
	AgentVerified bool   `json:"agent_verified"`
	Distro        string `json:"distro"`
	Release       string `json:"release"`
	KernelPackage string `json:"kernel_package"`
	KernelVersion string `json:"kernel_version"`
}

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
