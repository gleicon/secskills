package intel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const fixtureDir = "../../testdata/cve-2026-98432"

func loadFixture(t *testing.T) (Advisory, DistroState, []Asset) {
	t.Helper()
	var adv Advisory
	readJSON(t, filepath.Join(fixtureDir, "advisory.json"), &adv)
	var ds DistroState
	readJSON(t, filepath.Join(fixtureDir, "distro-state.json"), &ds)
	var wrap struct {
		Assets []Asset `json:"assets"`
	}
	readJSON(t, filepath.Join(fixtureDir, "assets.json"), &wrap)
	return adv, ds, wrap.Assets
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// TestCVE202698432ThreeTiers replays the fixture and asserts the spec AC-3
// outcome: four synthetic assets produce three distinct confidence tiers plus a
// non-candidate, and external data never claims a kernel patch state.
func TestCVE202698432ThreeTiers(t *testing.T) {
	adv, ds, assets := loadFixture(t)
	cands := Match(adv, ds, assets)

	byIP := map[string]Candidate{}
	for _, c := range cands {
		byIP[c.AssetIP] = c
	}

	// Windows host: not a candidate for a Linux kernel CVE.
	if _, ok := byIP["203.0.113.40"]; ok {
		t.Error("Windows host must not be a candidate for a Linux kernel CVE")
	}
	if len(cands) != 3 {
		t.Fatalf("want 3 candidates (L3, L1, L0), got %d: %+v", len(cands), cands)
	}

	// L3: agent-verified RHEL 9.8, kernel below fixed -> unpatched, verified.
	l3 := byIP["203.0.113.10"]
	if l3.Tier != "L3" || l3.Confidence != "verified" || l3.PatchState != "unpatched" {
		t.Errorf("agent asset: want L3/verified/unpatched, got %s/%s/%s", l3.Tier, l3.Confidence, l3.PatchState)
	}

	// L1: external MPTCP-capable -> kernel unknown, risk multiplier.
	l1 := byIP["203.0.113.20"]
	if l1.Tier != "L1" || l1.PatchState != "unknown" {
		t.Errorf("MPTCP asset: want L1/unknown, got %s/%s", l1.Tier, l1.PatchState)
	}
	if !l1.UrgentFeed {
		t.Error("L1 labelled candidate should be eligible for the urgent feed")
	}

	// L0: generic reachable Linux -> kernel unknown, NOT urgent (kernel UAF not in KEV).
	l0 := byIP["203.0.113.30"]
	if l0.Tier != "L0" || l0.PatchState != "unknown" {
		t.Errorf("generic asset: want L0/unknown, got %s/%s", l0.Tier, l0.PatchState)
	}
	if l0.UrgentFeed {
		t.Error("an L0 kernel guess must never enter the urgent feed (D-3)")
	}

	// The honesty invariant across every candidate (AC-3).
	for _, c := range cands {
		if c.Tier != "L3" && c.PatchState != "unknown" {
			t.Errorf("%s: external tier %s must not assert patch state, got %q", c.AssetIP, c.Tier, c.PatchState)
		}
	}
}

func TestKernelAtLeast(t *testing.T) {
	cases := []struct {
		installed, fixed string
		want             bool
	}{
		{"5.14.0-687.64.1.el9_8", "5.14.0-687.64.1.el9_8", true},  // equal
		{"5.14.0-570.12.1.el9_8", "5.14.0-687.64.1.el9_8", false}, // below
		{"5.14.0-700.1.1.el9_8", "5.14.0-687.64.1.el9_8", true},   // above
		{"6.1.112-122.0.amzn2023", "6.1.112-122.0.amzn2023", true},
	}
	for _, c := range cases {
		if got := kernelAtLeast(c.installed, c.fixed); got != c.want {
			t.Errorf("kernelAtLeast(%q,%q) = %v, want %v", c.installed, c.fixed, got, c.want)
		}
	}
}

// TestNoFalsePatchedWhenFixPending: an agent-verified asset on a release whose
// distro has not shipped a fix (wip/testing) is unpatched, never patched.
func TestNoFalsePatchedWhenFixPending(t *testing.T) {
	adv, ds, _ := loadFixture(t)
	a := Asset{IP: "203.0.113.50", OS: "linux", ReachableTCP: true, AgentVerified: true,
		Distro: "ubuntu", Release: "24.04", KernelPackage: "linux-image-generic", KernelVersion: "6.8.0-100.100"}
	c, ok := matchKernelReachable(adv, ds, a)
	if !ok || c.Tier != "L3" || c.PatchState != "unpatched" {
		t.Fatalf("ubuntu wip release must be L3/unpatched, got ok=%v %s/%s", ok, c.Tier, c.PatchState)
	}
}
