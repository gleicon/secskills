package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/probe"
)

func cmdFleet(args []string) error {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with candidates.jsonl + enriched-observations.jsonl")
	tenantsPath := fs.String("tenants", "", "tenants file (JSON array)")
	k := fs.Int("k", 2, "k-anonymity: suppress buckets seen in fewer than k tenants")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" || *tenantsPath == "" {
		return fmt.Errorf("usage: secskills fleet --workdir <dir> --tenants <file> [--k 2]")
	}
	if *k < 1 {
		return fmt.Errorf("--k must be >= 1")
	}
	tenants, err := exposure.LoadTenants(*tenantsPath)
	if err != nil {
		return fmt.Errorf("tenants: %w", err)
	}
	cands := exposure.LoadCandidates(filepath.Join(*wd, "candidates.jsonl"))
	obs, _ := probe.Load(filepath.Join(*wd, "enriched-observations.jsonl"))

	cveRows := exposure.AggregateFleet(tenants, cands, *k)
	stackRows := exposure.AggregateStacks(tenants, obs, *k)

	fmt.Printf("fleet intelligence — %d tenants, k=%d (anonymised: counts only)\n\n", len(tenants), *k)
	fmt.Println("top CVEs across the fleet:")
	fmt.Println("  tenants  hosts  KEV  CVE")
	for _, r := range cveRows {
		mark := "   "
		if r.Urgent {
			mark = "KEV"
		}
		fmt.Printf("  %-7d  %-5d  %s  %s\n", r.Tenants, r.Hosts, mark, r.Key)
	}
	if len(cveRows) == 0 {
		fmt.Printf("  (none shared by >= %d tenants)\n", *k)
	}
	fmt.Println("\ntop stacks across the fleet:")
	fmt.Println("  tenants  hosts  product")
	for _, r := range stackRows {
		fmt.Printf("  %-7d  %-5d  %s\n", r.Tenants, r.Hosts, r.Key)
	}
	if len(stackRows) == 0 {
		fmt.Printf("  (none shared by >= %d tenants)\n", *k)
	}
	return nil
}
