package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/probe"
)

// cmdPrefixReport renders an operator-facing exposure report for one swept
// block from its stored artifacts (observations.jsonl + leaks.jsonl). It is a
// read-only summary of what was already observed — it sends no traffic. The
// output is engagement data (host IPs, exposure locations) and is written to a
// file, never published; credential VALUES are never included (only the fact of
// exposure and the key names, so an administrator can rotate).
func cmdPrefixReport(args []string) error {
	fs := flag.NewFlagSet("prefix-report", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with observations.jsonl (and optional leaks.jsonl)")
	out := fs.String("output", "", "write the report here (default <workdir>/exposure-report.md)")
	label := fs.String("label", "", "scope label for the heading (e.g. AS64500 203.0.113.0/24)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("usage: secskills prefix-report --workdir <dir> [--label ...] [--output file]")
	}
	// Prefer the enriched observations (product/version) when an enrich pass has
	// run; fall back to the raw sweep output.
	obsPath := filepath.Join(*wd, "enriched-observations.jsonl")
	if _, err := os.Stat(obsPath); err != nil {
		obsPath = filepath.Join(*wd, "observations.jsonl")
	}
	obs, err := probe.Load(obsPath)
	if err != nil {
		return fmt.Errorf("load observations: %w", err)
	}
	leaks := exposure.LoadLeaks(filepath.Join(*wd, "leaks.jsonl"))    // optional
	dbc := exposure.LoadDBChecks(filepath.Join(*wd, "dbcheck.jsonl")) // optional

	report := exposure.RenderPrefixReport(*label, obs, leaks, dbc, exposure.LoadKEVForEnrich(), exposure.LoadCandidates(filepath.Join(*wd, "candidates.jsonl")))
	target := *out
	if target == "" {
		target = filepath.Join(*wd, "exposure-report.md")
	}
	if err := os.WriteFile(target, []byte(report), 0o600); err != nil {
		return err
	}
	fmt.Printf("exposure report -> %s (%d bytes)\n", target, len(report))
	return nil
}
