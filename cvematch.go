package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/probe"
)

// cmdCVEMatch joins enriched observations against the cached NVD version ranges
// (spec FR-4) and emits per-host CVE candidates. Each candidate is version-
// inferred (L1, PatchState unknown): a banner version in an affected range is a
// lead to confirm, not a confirmed finding, because a distro backport may have
// patched the CVE behind an unchanged version string. KEV membership escalates a
// match to the urgent feed.
func cmdCVEMatch(args []string) error {
	fs := flag.NewFlagSet("cvematch", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with enriched-observations.jsonl")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("usage: secskills cvematch --workdir <dir>")
	}
	path := filepath.Join(*wd, "enriched-observations.jsonl")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no enriched observations — run `secskills enrich` first: %w", err)
	}
	obs, err := probe.Load(path)
	if err != nil {
		return err
	}
	ranges := loadVulnRanges()
	if len(ranges) == 0 {
		return fmt.Errorf("no cached NVD ranges — run `secskills feed nvd --product <name>` first")
	}
	kev := kevCVESet()

	var cands []intel.Candidate
	seen := map[string]bool{}
	for _, o := range obs {
		for _, c := range intel.MatchProduct(o.IP, o.Product, o.Version, ranges) {
			key := c.AssetIP + "|" + c.CVE
			if seen[key] {
				continue
			}
			seen[key] = true
			if kev[c.CVE] {
				c.UrgentFeed = true
			}
			cands = append(cands, c)
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].UrgentFeed != cands[j].UrgentFeed {
			return cands[i].UrgentFeed
		}
		return cands[i].AssetIP < cands[j].AssetIP
	})

	out := filepath.Join(*wd, "candidates.jsonl")
	os.Remove(out)
	for _, c := range cands {
		appendJSONL(out, c)
	}

	urgent := 0
	for _, c := range cands {
		if c.UrgentFeed {
			urgent++
		}
	}
	fmt.Printf("cvematch: %d version-inferred CVE candidates (%d KEV-urgent) -> %s\n", len(cands), urgent, out)
	for _, c := range cands {
		mark := "  "
		if c.UrgentFeed {
			mark = "KEV"
		}
		fmt.Printf("%s %-16s %-16s %s\n", mark, c.AssetIP, c.CVE, c.Claim)
	}
	return nil
}

// kevCVESet returns the set of CVE ids currently in the cached KEV catalog.
func kevCVESet() map[string]bool {
	s := map[string]bool{}
	for _, e := range loadKEVForEnrich() {
		s[e.CVE] = true
	}
	return s
}
