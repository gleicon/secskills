package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/gleicon/secskills/internal/intel"
)

// cmdMatch runs the deterministic vulnerability matcher (spec FR-4) over a
// fixture directory and renders the candidates plus a one-screen brief (§11.3).
// It is the offline replay of the CVE-2026-98432 pipeline: advisory + distro
// state + assets -> tier-labelled candidates, no network and no model. The same
// matcher runs online once observations and the feed ingest exist.
func cmdMatch(args []string) error {
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	dir := fs.String("fixture", "testdata/cve-2026-98432", "directory with advisory.json, distro-state.json, assets.json")
	asJSON := fs.Bool("json", false, "emit candidates as JSON instead of the brief")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var adv intel.Advisory
	if err := readJSONFile(filepath.Join(*dir, "advisory.json"), &adv); err != nil {
		return err
	}
	var ds intel.DistroState
	if err := readJSONFile(filepath.Join(*dir, "distro-state.json"), &ds); err != nil {
		return err
	}
	var wrap struct {
		Assets []intel.Asset `json:"assets"`
	}
	if err := readJSONFile(filepath.Join(*dir, "assets.json"), &wrap); err != nil {
		return err
	}

	cands := intel.Match(adv, ds, wrap.Assets)
	if *asJSON {
		b, _ := json.MarshalIndent(cands, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printBrief(adv, cands)
	return nil
}

func readJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// printBrief renders the one-screen brief (spec §11.3): urgent-feed candidates
// first (tier before score, D-3), each a single honest line. External tiers
// never print a patch verdict.
func printBrief(adv intel.Advisory, cands []intel.Candidate) {
	// Sort by urgent first, then tier (L3>L2>L1>L0), then score.
	tierRank := map[string]int{"L3": 3, "L2": 2, "L1": 1, "L0": 0}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].UrgentFeed != cands[j].UrgentFeed {
			return cands[i].UrgentFeed
		}
		if tierRank[cands[i].Tier] != tierRank[cands[j].Tier] {
			return tierRank[cands[i].Tier] > tierRank[cands[j].Tier]
		}
		return cands[i].Score > cands[j].Score
	})

	fmt.Printf("TODAY · %s (CVSS %.1f, KEV=%v, PoC=%d) · %d candidates\n", adv.ID, adv.CVSS, adv.KEV, adv.POCSignal, len(cands))
	n := 0
	for _, c := range cands {
		if !c.UrgentFeed {
			continue
		}
		n++
		fmt.Printf("%d. %-15s [%s %s] %s\n", n, c.AssetIP, c.Tier, c.Confidence, c.Claim)
	}
	if n == 0 {
		fmt.Println("(nothing in the urgent feed — kernel UAF not in KEV; external tiers do not escalate)")
	}
	// Non-urgent (L0) are listed below the line, never as a verdict.
	for _, c := range cands {
		if c.UrgentFeed {
			continue
		}
		fmt.Printf("   · %-15s [%s] %s\n", c.AssetIP, c.Tier, c.Claim)
	}
}
