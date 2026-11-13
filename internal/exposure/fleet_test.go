package exposure

import (
	"testing"
	"time"

	"github.com/gleicon/secskills/internal/intel"
)

var twoTenants = []Tenant{
	{Tenant: "acme", Prefixes: []string{"203.0.113.0/24"}},
	{Tenant: "beycorp", Prefixes: []string{"198.51.100.0/24"}},
}

// FR-9: a CVE in >= k tenants is reported (counts only); one in a single tenant
// is suppressed by k-anonymity.
func TestAggregateFleetKAnonymity(t *testing.T) {
	cands := []intel.Candidate{
		{AssetIP: "203.0.113.10", CVE: "CVE-SHARED"}, // acme
		{AssetIP: "198.51.100.5", CVE: "CVE-SHARED"}, // beycorp -> 2 tenants
		{AssetIP: "203.0.113.11", CVE: "CVE-ACME"},   // acme only
	}
	rows := AggregateFleet(twoTenants, cands, 2)
	if len(rows) != 1 || rows[0].Key != "CVE-SHARED" {
		t.Fatalf("expected only CVE-SHARED to survive k=2, got %+v", rows)
	}
	if rows[0].Tenants != 2 || rows[0].Hosts != 2 {
		t.Fatalf("CVE-SHARED should be 2 tenants / 2 hosts, got %+v", rows[0])
	}
}

// NFR-1/AC-2: a synthetic KEV event notifies the right tenant with the right
// asset, and the latency is the join time (event_at=now -> ~0), never a scan.
func TestNotifyForCVEsLatencyAndScope(t *testing.T) {
	cands := []intel.Candidate{
		{AssetIP: "203.0.113.10", CVE: "CVE-2026-98432"},
		{AssetIP: "198.51.100.5", CVE: "CVE-2026-98432"},
	}
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	eventAt := map[string]time.Time{"CVE-2026-98432": now.Add(-5 * time.Minute)}
	notes := NotifyForCVEs(twoTenants, cands, eventAt, now)
	if len(notes) != 2 {
		t.Fatalf("expected one notification per tenant, got %d", len(notes))
	}
	for _, n := range notes {
		if n.LatencySec != 300 {
			t.Fatalf("latency should be 300s (5 min), got %.0f", n.LatencySec)
		}
		if n.Tenant == "acme" && (len(n.Assets) != 1 || n.Assets[0] != "203.0.113.10") {
			t.Fatalf("acme notification carries wrong asset: %v", n.Assets)
		}
		if n.Tenant == "acme" {
			for _, a := range n.Assets {
				if a == "198.51.100.5" {
					t.Fatalf("CROSS-TENANT LEAK in notification: %s", a)
				}
			}
		}
	}
}
