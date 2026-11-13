package exposure

import (
	"sort"
	"testing"

	"github.com/gleicon/secskills/internal/intel"
)

func TestAllowedTransition(t *testing.T) {
	ok := [][2]string{{"open", "confirmed"}, {"open", "fixed"}, {"confirmed", "accepted_risk"},
		{"accepted_risk", "fixed"}, {"fixed", "open"}, {"false_positive", "open"}, {"open", "open"}}
	for _, p := range ok {
		if !AllowedTransition(p[0], p[1]) {
			t.Errorf("%s->%s should be allowed", p[0], p[1])
		}
	}
	bad := [][2]string{{"fixed", "confirmed"}, {"false_positive", "fixed"}, {"confirmed", "open"}}
	for _, p := range bad {
		if AllowedTransition(p[0], p[1]) {
			t.Errorf("%s->%s should be illegal", p[0], p[1])
		}
	}
}

func TestReconcileNewAndFixed(t *testing.T) {
	store := map[string]LifeFinding{}
	c1 := []intel.Candidate{{AssetIP: "1.1.1.1", CVE: "CVE-A"}, {AssetIP: "1.1.1.1", CVE: "CVE-B"}}

	// First reconcile: both open.
	store, log := Reconcile(store, c1, "t0")
	if len(store) != 2 || store["1.1.1.1|CVE-A"].State != "open" {
		t.Fatalf("new candidates must be open: %+v", store)
	}
	_ = log

	// Second reconcile: CVE-B gone (host patched) -> fixed, re-verified.
	c2 := []intel.Candidate{{AssetIP: "1.1.1.1", CVE: "CVE-A"}}
	store, _ = Reconcile(store, c2, "t1")
	if store["1.1.1.1|CVE-B"].State != "fixed" || store["1.1.1.1|CVE-B"].FixedAt == "" {
		t.Fatalf("disappeared candidate must be fixed/re-verified: %+v", store["1.1.1.1|CVE-B"])
	}
	if store["1.1.1.1|CVE-A"].State != "open" {
		t.Error("still-present candidate stays open")
	}
}

func TestReconcilePreservesManualAndRegresses(t *testing.T) {
	// accepted_risk must survive a reconcile while its candidate is present.
	store := map[string]LifeFinding{
		"2.2.2.2|CVE-X": {IP: "2.2.2.2", CVE: "CVE-X", State: "accepted_risk", FirstSeen: "t0"},
		"2.2.2.2|CVE-Y": {IP: "2.2.2.2", CVE: "CVE-Y", State: "fixed", FixedAt: "t0"},
	}
	cur := []intel.Candidate{
		{AssetIP: "2.2.2.2", CVE: "CVE-X"}, // still accepted_risk
		{AssetIP: "2.2.2.2", CVE: "CVE-Y"}, // reappeared -> regressed to open
	}
	store, _ = Reconcile(store, cur, "t1")
	if store["2.2.2.2|CVE-X"].State != "accepted_risk" {
		t.Error("accepted_risk must be preserved while present")
	}
	if store["2.2.2.2|CVE-Y"].State != "open" {
		t.Errorf("a fixed finding whose candidate reappears must regress to open, got %s", store["2.2.2.2|CVE-Y"].State)
	}
}

func TestReconcileLogIsSorted(t *testing.T) {
	var cands []intel.Candidate
	for _, ip := range []string{"203.0.113.9", "203.0.113.1", "203.0.113.5", "203.0.113.3"} {
		cands = append(cands, intel.Candidate{AssetIP: ip, CVE: "CVE-2024-0001"})
	}
	stored := map[string]LifeFinding{
		"198.51.100.2|CVE-2024-0002": {IP: "198.51.100.2", CVE: "CVE-2024-0002", State: "open"},
		"198.51.100.1|CVE-2024-0002": {IP: "198.51.100.1", CVE: "CVE-2024-0002", State: "open"},
	}
	for i := 0; i < 20; i++ {
		_, log := Reconcile(stored, cands, "now")
		if !sort.StringsAreSorted(log) || len(log) != 6 {
			t.Fatalf("log not sorted/complete: %v", log)
		}
	}
}
