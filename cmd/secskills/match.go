package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
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
	if err := exposure.ReadJSONFile(filepath.Join(*dir, "advisory.json"), &adv); err != nil {
		return err
	}
	var ds intel.DistroState
	if err := exposure.ReadJSONFile(filepath.Join(*dir, "distro-state.json"), &ds); err != nil {
		return err
	}
	var wrap struct {
		Assets []intel.Asset `json:"assets"`
	}
	if err := exposure.ReadJSONFile(filepath.Join(*dir, "assets.json"), &wrap); err != nil {
		return err
	}

	cands := intel.Match(adv, ds, wrap.Assets)
	if *asJSON {
		b, _ := json.MarshalIndent(cands, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	exposure.PrintBrief(adv, cands)
	return nil
}
