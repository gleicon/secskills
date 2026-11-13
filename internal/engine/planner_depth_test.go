package engine

import (
	"os"
	"testing"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
)

// TestPlannerChainDepth proves the planner chains beyond one step: a Prometheus
// disclosure reveals an internal hostname that resolves publicly (round 1), which
// the planner then fingerprints as a newly-reachable host (round 2) — producing
// an attack-graph edge at depth >= 2.
func TestPlannerChainDepth(t *testing.T) {
	netsec.AllowLocalProbes = true
	defer func() { netsec.AllowLocalProbes = false }()
	wd, _ := os.MkdirTemp("", "sk-depth")
	defer os.RemoveAll(wd)
	src := finding.Finding{
		Title: "Unauthenticated Prometheus metrics", Host: "https://h.example.com",
		DetectorID: "http.prometheus.public-metrics@1", Validation: "behavior-confirmed",
		Capabilities: []string{finding.CapAnonRead, finding.CapInternalHosts},
		Pivots:       []string{"internal_host=example.com"}, // resolves publicly
	}
	RunPlanner(wd, "h.example.com", []finding.Finding{src})
	edges := loadPlannerGraph(wd)
	maxDepth := 0
	sawT1 := false
	for _, e := range edges {
		if e.Depth > maxDepth {
			maxDepth = e.Depth
		}
		if e.FromCap == finding.CapPublicService {
			sawT1 = true
		}
	}
	if maxDepth < 2 {
		t.Errorf("planner max depth = %d, want >= 2 (no multi-step chain)", maxDepth)
	}
	if !sawT1 {
		t.Error("planner did not chain into a publicly_resolvable_service follow-up decision")
	}
}
