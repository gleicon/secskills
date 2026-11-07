package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/probe"
)

// Fleet intelligence (spec FR-9): an aggregate, ANONYMISED ranking of the CVEs
// and stacks common across tenants. The point is cross-tenant prioritisation
// ("this CVE is everywhere") without exposing who is affected, so the output
// carries counts only — never a tenant id, never an asset IP — and a bucket seen
// in fewer than k tenants is suppressed (k-anonymity): a finding in a single
// tenant is that tenant's business, not fleet intelligence.
type fleetRow struct {
	Key     string // CVE id or product
	Tenants int    // distinct tenants affected
	Hosts   int    // distinct hosts across the fleet
	Urgent  bool   // KEV on any tenant
}

// aggregateFleet counts CVE prevalence across tenants from the shared candidate
// set, suppressing anything under k tenants. Pure, so the test needs no files.
func aggregateFleet(tenants []Tenant, cands []intel.Candidate, k int) []fleetRow {
	type agg struct {
		tenants map[string]bool
		hosts   map[string]bool
		urgent  bool
	}
	m := map[string]*agg{}
	for _, t := range tenants {
		for _, c := range tenantFilter(cands, t) {
			a := m[c.CVE]
			if a == nil {
				a = &agg{tenants: map[string]bool{}, hosts: map[string]bool{}}
				m[c.CVE] = a
			}
			a.tenants[t.Tenant] = true
			a.hosts[c.AssetIP] = true
			if c.UrgentFeed {
				a.urgent = true
			}
		}
	}
	var rows []fleetRow
	for cve, a := range m {
		if len(a.tenants) < k {
			continue // k-anonymity: not fleet-wide enough to report
		}
		rows = append(rows, fleetRow{Key: cve, Tenants: len(a.tenants), Hosts: len(a.hosts), Urgent: a.urgent})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Tenants != rows[j].Tenants {
			return rows[i].Tenants > rows[j].Tenants
		}
		if rows[i].Hosts != rows[j].Hosts {
			return rows[i].Hosts > rows[j].Hosts
		}
		return rows[i].Key < rows[j].Key
	})
	return rows
}

// aggregateStacks ranks products across the fleet the same way, from enriched
// observations. tenantOfIP maps an observation to its tenant; an observation
// outside every tenant is ignored (never attributed, never leaked).
func aggregateStacks(tenants []Tenant, obs []probe.Observation, k int) []fleetRow {
	type agg struct {
		tenants map[string]bool
		hosts   map[string]bool
	}
	m := map[string]*agg{}
	for _, o := range obs {
		if o.Product == "" {
			continue
		}
		tn := tenantOfIP(tenants, o.IP)
		if tn == "" {
			continue
		}
		a := m[o.Product]
		if a == nil {
			a = &agg{tenants: map[string]bool{}, hosts: map[string]bool{}}
			m[o.Product] = a
		}
		a.tenants[tn] = true
		a.hosts[o.IP] = true
	}
	var rows []fleetRow
	for p, a := range m {
		if len(a.tenants) < k {
			continue
		}
		rows = append(rows, fleetRow{Key: p, Tenants: len(a.tenants), Hosts: len(a.hosts)})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Tenants != rows[j].Tenants {
			return rows[i].Tenants > rows[j].Tenants
		}
		if rows[i].Hosts != rows[j].Hosts {
			return rows[i].Hosts > rows[j].Hosts
		}
		return rows[i].Key < rows[j].Key
	})
	return rows
}

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
	tenants, err := loadTenants(*tenantsPath)
	if err != nil {
		return fmt.Errorf("tenants: %w", err)
	}
	cands := loadCandidates(filepath.Join(*wd, "candidates.jsonl"))
	obs, _ := probe.Load(filepath.Join(*wd, "enriched-observations.jsonl"))

	cveRows := aggregateFleet(tenants, cands, *k)
	stackRows := aggregateStacks(tenants, obs, *k)

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
