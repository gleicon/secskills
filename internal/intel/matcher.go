package intel

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// confidenceWeight maps a tier's confidence label to the scoring multiplier
// (spec §10). Kept here so the score is reproducible from the candidate alone.
var confidenceWeight = map[string]float64{"low": 0.3, "medium": 0.6, "high": 0.9, "verified": 1.0}

// Match joins one advisory, its distro state, and a set of assets into
// candidates, one per affected asset. It is deterministic and model-free.
//
// Tier assignment for a kernel advisory (RequiresReachableTCP):
//
//	L3  agent-verified distro/release/kernel  -> patch state decided, patched or unpatched
//	L1  external, MPTCP listener reachable     -> kernel unknown, risk multiplier
//	L0  external, reachable Linux TCP          -> kernel unknown
//	--  Windows, or no reachable TCP           -> not a candidate
//
// The honesty invariant: PatchState is "unknown" for every non-L3 candidate;
// only L3 may be "patched"/"unpatched" (enforced here and asserted in tests).
func Match(adv Advisory, ds DistroState, assets []Asset) []Candidate {
	var out []Candidate
	for _, a := range assets {
		c, ok := matchKernelReachable(adv, ds, a)
		if !ok {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AssetIP < out[j].AssetIP })
	return out
}

func matchKernelReachable(adv Advisory, ds DistroState, a Asset) (Candidate, bool) {
	// Linux-only kernel CVE: a non-Linux OS is never a candidate.
	if a.OS == "windows" {
		return Candidate{}, false
	}
	// Exposure precondition: a kernel bug reachable before auth needs a
	// reachable TCP port. No reachable port and no agent -> not exposed.
	if adv.RequiresReachableTCP && !a.ReachableTCP && !a.AgentVerified {
		return Candidate{}, false
	}

	base := Candidate{AssetIP: a.IP, CVE: adv.ID, Remediation: adv.Remediation.Default}

	switch {
	case a.AgentVerified && a.Distro != "" && a.KernelVersion != "":
		// L3: the only tier allowed to state patch state.
		base.Tier = "L3"
		base.Confidence = "verified"
		patched, lag := kernelPatched(ds, a)
		if patched {
			base.PatchState = "patched"
			base.Claim = fmt.Sprintf("agent-verified: kernel %s is at or above the fixed release for %s %s", a.KernelVersion, a.Distro, a.Release)
		} else {
			base.PatchState = "unpatched"
			base.Claim = fmt.Sprintf("agent-verified: kernel %s is below the fixed release for %s %s", a.KernelVersion, a.Distro, a.Release)
		}
		base.Score, base.ScoreTerms = score(adv, base.Confidence, 1, lag)

	case adv.MPTCPMultiplier && a.MPTCPCapable:
		// L1: external, one probe. Reachability of the PoC's setup, not patch state.
		base.Tier = "L1"
		base.Confidence = "medium"
		base.PatchState = "unknown"
		base.Claim = "MPTCP listener reachable; kernel patch state unknown — agent or nft mitigation required"
		base.Remediation = adv.Remediation.Mitigation
		base.Score, base.ScoreTerms = score(adv, base.Confidence, 1, 0)

	default:
		// L0: external, cached observation only. Reachable, kernel unknown.
		base.Tier = "L0"
		base.Confidence = "low"
		base.PatchState = "unknown"
		base.Claim = "reachable TCP service on a Linux host; kernel patch state unknown — agent required"
		base.Score, base.ScoreTerms = score(adv, base.Confidence, 1, 0)
	}

	// D-3: the urgent feed admits L1+ labelled, or an L0 only when KEV and an
	// exact product/version match (which external kernel evidence never is). A
	// kernel UAF not in KEV therefore never enters the urgent feed from L0.
	base.UrgentFeed = base.Tier != "L0"

	// Invariant guard: no external tier may assert patch state.
	if base.Tier != "L3" && base.PatchState != "unknown" {
		base.PatchState = "unknown"
	}
	return base, true
}

// kernelPatched compares an agent-verified asset's kernel against the distro
// tracker's fixed version. Returns patched and the patch-lag term (0 when
// patched or when the fix is not yet shipped for the release).
func kernelPatched(ds DistroState, a Asset) (patched bool, lag float64) {
	e, ok := ds.find(a.Distro, a.Release, a.KernelPackage)
	if !ok || e.Status != "fixed" || e.FixedVersion == "" {
		// No fix shipped for this release yet (wip/testing) -> unpatched, max lag.
		return false, 1.0
	}
	if kernelAtLeast(a.KernelVersion, e.FixedVersion) {
		return true, 0
	}
	return false, 1.0
}

// kernelAtLeast reports whether installed >= fixed by comparing their numeric
// tokens left to right. Distro kernel strings mix dots and dashes
// (5.14.0-687.64.1.el9_8); non-digit runs are separators and the trailing
// distro tag is ignored once the numeric sequences diverge.
func kernelAtLeast(installed, fixed string) bool {
	ai, af := numericTokens(installed), numericTokens(fixed)
	for i := 0; i < len(ai) && i < len(af); i++ {
		if ai[i] != af[i] {
			return ai[i] > af[i]
		}
	}
	return len(ai) >= len(af)
}

// numericTokens splits s on non-digit runs and returns the integer value of
// each digit run, stopping at the distro tag (a token containing "el", "amzn",
// etc. is still numeric-split; the leading kernel numbers dominate the compare).
func numericTokens(s string) []int {
	var out []int
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			if n, err := strconv.Atoi(cur.String()); err == nil {
				out = append(out, n)
			}
			cur.Reset()
		}
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// score computes risk = exposed × confidence × (w_poc·PoC + w_lag·patch_lag) and
// records the named terms (spec §10). Criticality defaults to 1 here; the
// engine multiplies in asset criticality downstream.
func score(adv Advisory, confidence string, exposed int, lag float64) (float64, map[string]float64) {
	const wPOC, wLag = 0.6, 0.4
	poc := float64(adv.POCSignal) / 10.0
	if poc > 1 {
		poc = 1
	}
	conf := confidenceWeight[confidence]
	risk := float64(exposed) * conf * (wPOC*poc + wLag*lag)
	terms := map[string]float64{
		"exposed":    float64(exposed),
		"confidence": conf,
		"poc":        poc,
		"patch_lag":  lag,
	}
	return risk, terms
}
