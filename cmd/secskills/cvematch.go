package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/jsonl"
	"github.com/gleicon/secskills/internal/probe"
)

// cmdCVEMatch joins enriched observations with the cached NVD version ranges
// (spec FR-4). Every match is version-inferred: a banner version in an affected
// range is a lead to confirm, because a distro backport may have fixed the CVE
// behind an unchanged version string. Each matched service becomes one finding
// (KEV-listed CVEs first); services that no longer match are closed.
func cmdCVEMatch(args []string) error {
	fs := flag.NewFlagSet("cvematch", flag.ContinueOnError)
	wdFlag := fs.String("workdir", "", "workdir with enriched-observations.jsonl (default: the target's workdir)")
	save := fs.Bool("save", true, "save a run for report/retest")
	target, wd, err := blockTarget(fs, args, wdFlag, "secskills cvematch <block> [--workdir dir]")
	if err != nil {
		return err
	}
	path := filepath.Join(wd, "enriched-observations.jsonl")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no enriched observations — run `secskills enrich` first: %w", err)
	}
	obs, err := probe.Load(path)
	if err != nil {
		return err
	}
	ranges := exposure.LoadVulnRanges()
	if len(ranges) == 0 {
		return fmt.Errorf("no cached NVD ranges — run `secskills feed nvd --product <name>` first")
	}
	kev := exposure.KEVCVESet()

	matches := make([]exposure.ServiceMatch, 0, len(obs))
	cveSet := map[string]bool{}
	for _, o := range obs {
		cs := intel.MatchProduct(o.IP, o.Product, o.Version, ranges)
		if len(cs) == 0 {
			continue
		}
		for _, c := range cs {
			cveSet[c.CVE] = true
		}
		matches = append(matches, exposure.ServiceMatch{Obs: o, Cands: cs})
	}

	// EPSS weighting so the non-KEV tail is ranked by exploit likelihood:
	// score = confidence x (w_kev.KEV + w_epss.EPSS + w_cvss.CVSS/10).
	distinct := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		distinct = append(distinct, cve)
	}
	sort.Strings(distinct)
	epss := exposure.EPSSLookup(distinct)
	var cands []intel.Candidate
	seen := map[string]bool{}
	for i := range matches {
		for j := range matches[i].Cands {
			c := &matches[i].Cands[j]
			kevTerm := 0.0
			if kev[c.CVE] {
				c.UrgentFeed, kevTerm = true, 1.0
			}
			c.ScoreTerms["epss"] = epss[c.CVE]
			c.ScoreTerms["kev"] = kevTerm
			c.Score = exposure.CandidateScore(kevTerm, epss[c.CVE], c.ScoreTerms["cvss"])
			if key := c.AssetIP + "|" + c.CVE; !seen[key] {
				seen[key] = true
				cands = append(cands, *c)
			}
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].UrgentFeed != cands[j].UrgentFeed {
			return cands[i].UrgentFeed
		}
		if cands[i].Score != cands[j].Score {
			return cands[i].Score > cands[j].Score
		}
		if cands[i].AssetIP != cands[j].AssetIP {
			return cands[i].AssetIP < cands[j].AssetIP
		}
		return cands[i].CVE < cands[j].CVE
	})

	out := filepath.Join(wd, "candidates.jsonl")
	os.Remove(out)
	urgent := 0
	for _, c := range cands {
		jsonl.AppendJSONL(out, c)
		if c.UrgentFeed {
			urgent++
		}
	}
	fmt.Printf("cvematch: %d version-inferred CVE candidates (%d KEV-listed) on %d services -> %s\n", len(cands), urgent, len(matches), out)
	return syncAndSave(target, wd, exposure.FamilyCVE, exposure.CVEFindings(matches, kev), *save)
}
