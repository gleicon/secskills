package main

import (
	"flag"
	"fmt"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/workspace"
)

// blockTarget resolves a network-block command's workdir. The positional
// target is the block exactly as given to discover (203.0.113.0/24, AS64500)
// and selects the same workdir and findings store as report, tickets and
// export. --workdir overrides the directory, e.g. for a carried capture.
func blockTarget(fs *flag.FlagSet, args []string, wd *string, usage string) (target, dir string, err error) {
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return "", "", err
	}
	if len(pos) > 0 {
		target = pos[0]
	}
	switch {
	case *wd != "":
		return target, *wd, nil
	case target != "":
		dir, err := workspace.Workdir(target)
		return target, dir, err
	}
	return "", "", fmt.Errorf("usage: %s", usage)
}

// syncAndSave writes one family of network findings and, when the target is
// known, saves a run so retest, watch, attest and diffs work on the block.
func syncAndSave(target, wd, family string, fs []finding.Finding, save bool) error {
	res, err := exposure.SyncFindings(wd, family, fs)
	if err != nil {
		return err
	}
	fmt.Printf("findings: %s\n", res)
	if !save {
		return nil
	}
	if target == "" {
		fmt.Println("(no target given; pass the block, e.g. `203.0.113.0/24`, to save a run for report/retest)")
		return nil
	}
	path, err := finding.WriteRun(target, wd, "network")
	if err != nil {
		return err
	}
	fmt.Printf("run saved: %s\nnext: secskills report --render %s\n", path, target)
	return nil
}
