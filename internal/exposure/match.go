package exposure

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/gleicon/secskills/internal/intel"
)

// ReadJSONFile decodes a JSON file into v.
func ReadJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// PrintBrief renders the one-screen brief (spec §11.3): urgent-feed candidates
// first (tier before score, D-3), each a single honest line. External tiers
// never print a patch verdict.
func PrintBrief(adv intel.Advisory, cands []intel.Candidate) {
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
