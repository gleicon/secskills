package main

import (
	"os"
	"testing"
)

// TestPlannerChainDepth proves the planner chains beyond one step: a Prometheus
// disclosure reveals an internal hostname that resolves publicly (round 1), which
// the planner then fingerprints as a newly-reachable host (round 2) — producing
// an attack-graph edge at depth >= 2.
func TestPlannerChainDepth(t *testing.T) {
	allowLocalProbes = true
	defer func() { allowLocalProbes = false }()
	wd, _ := os.MkdirTemp("", "sk-depth")
	defer os.RemoveAll(wd)
	src := Finding{
		Title: "Unauthenticated Prometheus metrics", Host: "https://h.example.com",
		DetectorID: "http.prometheus.public-metrics@1", Validation: "behavior-confirmed",
		Capabilities: []string{capAnonRead, capInternalHosts},
		Pivots:       []string{"internal_host=example.com"}, // resolves publicly
	}
	runPlanner(wd, "h.example.com", []Finding{src})
	edges := loadPlannerGraph(wd)
	maxDepth := 0
	sawT1 := false
	for _, e := range edges {
		if e.Depth > maxDepth {
			maxDepth = e.Depth
		}
		if e.FromCap == capPublicService {
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
