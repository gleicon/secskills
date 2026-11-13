package exposure

import (
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
type FleetRow struct {
	Key     string // CVE id or product
	Tenants int    // distinct tenants affected
	Hosts   int    // distinct hosts across the fleet
	Urgent  bool   // KEV on any tenant
}

// AggregateFleet counts CVE prevalence across tenants from the shared candidate
// set, suppressing anything under k tenants. Pure, so the test needs no files.
func AggregateFleet(tenants []Tenant, cands []intel.Candidate, k int) []FleetRow {
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
	var rows []FleetRow
	for cve, a := range m {
		if len(a.tenants) < k {
			continue // k-anonymity: not fleet-wide enough to report
		}
		rows = append(rows, FleetRow{Key: cve, Tenants: len(a.tenants), Hosts: len(a.hosts), Urgent: a.urgent})
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

// AggregateStacks ranks products across the fleet the same way, from enriched
// observations. tenantOfIP maps an observation to its tenant; an observation
// outside every tenant is ignored (never attributed, never leaked).
func AggregateStacks(tenants []Tenant, obs []probe.Observation, k int) []FleetRow {
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
	var rows []FleetRow
	for p, a := range m {
		if len(a.tenants) < k {
			continue
		}
		rows = append(rows, FleetRow{Key: p, Tenants: len(a.tenants), Hosts: len(a.hosts)})
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
