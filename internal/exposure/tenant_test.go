package exposure

import (
	"testing"

	"github.com/gleicon/secskills/internal/intel"
)

func cand(ip, cve string) intel.Candidate {
	return intel.Candidate{AssetIP: ip, CVE: cve, ScoreTerms: map[string]float64{}}
}

// AC-6: a read scoped to one tenant must never return another tenant's asset.
func TestTenantFilterIsolation(t *testing.T) {
	acme := Tenant{Tenant: "acme", ASN: 64500, Prefixes: []string{"203.0.113.0/24"}}
	bey := Tenant{Tenant: "beycorp", ASN: 64501, Prefixes: []string{"198.51.100.0/24"}}
	all := []intel.Candidate{
		cand("203.0.113.10", "CVE-2024-6387"),
		cand("198.51.100.5", "CVE-2023-44487"),
		cand("203.0.113.11", "CVE-2021-41773"),
	}

	a := tenantFilter(all, acme)
	if len(a) != 2 {
		t.Fatalf("acme should see 2 of its own, got %d", len(a))
	}
	for _, c := range a {
		if c.AssetIP == "198.51.100.5" {
			t.Fatalf("CROSS-TENANT LEAK: acme feed contains beycorp asset %s", c.AssetIP)
		}
	}
	b := tenantFilter(all, bey)
	if len(b) != 1 || b[0].AssetIP != "198.51.100.5" {
		t.Fatalf("beycorp should see exactly its own asset, got %v", b)
	}
}

// An unparseable or out-of-prefix IP is excluded, never leaked by default.
func TestTenantFilterExcludesUnknown(t *testing.T) {
	acme := Tenant{Tenant: "acme", Prefixes: []string{"203.0.113.0/24"}}
	got := tenantFilter([]intel.Candidate{cand("not-an-ip", "CVE-1"), cand("10.0.0.1", "CVE-2")}, acme)
	if len(got) != 0 {
		t.Fatalf("expected 0 (nothing in tenant), got %d", len(got))
	}
}

func TestBuildTenantFeedSortsUrgentFirst(t *testing.T) {
	acme := Tenant{Tenant: "acme", Prefixes: []string{"203.0.113.0/24"}}
	c1 := cand("203.0.113.10", "CVE-A")
	c1.Score = 0.9
	c2 := cand("203.0.113.11", "CVE-B")
	c2.UrgentFeed = true
	c2.Score = 0.1
	feed := BuildTenantFeed(acme, []intel.Candidate{c1, c2}, "2026-11-07T00:00:00Z")
	if feed.Count != 2 || feed.UrgentCount != 1 {
		t.Fatalf("count=%d urgent=%d", feed.Count, feed.UrgentCount)
	}
	if !feed.Findings[0].UrgentFeed {
		t.Fatalf("urgent candidate must sort first, got %s", feed.Findings[0].CVE)
	}
}
