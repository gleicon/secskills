package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/finding"
)

func cmdLifecycle(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills lifecycle <reconcile|set> --workdir <dir> ...")
	}
	fs := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with candidates.jsonl")
	ip := fs.String("ip", "", "set: finding IP")
	cve := fs.String("cve", "", "set: finding CVE")
	state := fs.String("state", "", "set: target state (confirmed|accepted_risk|false_positive)")
	note := fs.String("note", "", "set: optional note")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("--workdir is required")
	}
	storePath := filepath.Join(*wd, "findings.jsonl")
	store := exposure.LoadFindings(storePath)

	switch args[0] {
	case "reconcile":
		cands := exposure.LoadCandidates(filepath.Join(*wd, "candidates.jsonl"))
		updated, log := exposure.Reconcile(store, cands, finding.NowRFC())
		if err := exposure.SaveFindings(storePath, updated); err != nil {
			return err
		}
		counts := map[string]int{}
		for _, f := range updated {
			counts[f.State]++
		}
		fmt.Printf("lifecycle reconcile: %d findings tracked -> %s\n", len(updated), storePath)
		fmt.Printf("  states: %v\n", counts)
		for _, l := range log {
			fmt.Println("  " + l)
		}
		return nil
	case "set":
		if *ip == "" || *cve == "" || *state == "" {
			return fmt.Errorf("set requires --ip --cve --state")
		}
		key := *ip + "|" + *cve
		f, ok := store[key]
		if !ok {
			return fmt.Errorf("no finding %s", key)
		}
		if !exposure.AllowedTransition(f.State, *state) {
			return fmt.Errorf("illegal transition %s -> %s for %s", f.State, *state, key)
		}
		f.State, f.LastSeen = *state, finding.NowRFC()
		if *note != "" {
			f.Note = *note
		}
		store[key] = f
		if err := exposure.SaveFindings(storePath, store); err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", key, *state)
		return nil
	default:
		return fmt.Errorf("unknown lifecycle subcommand %q (want reconcile|set)", args[0])
	}
}
