package main

import (
	"os"
	"strings"
	"testing"
)

// TestPlannerInternalHostPivot proves the runtime planner turns a disclosed
// internal hostname that actually resolves publicly into a MEDIUM finding + a
// persisted attack-graph edge (real stateful chaining, not prose).
func TestPlannerInternalHostPivot(t *testing.T) {
	wd, _ := os.MkdirTemp("", "sk-planner-test")
	defer os.RemoveAll(wd)
	// a "disclosed internal host" that is in fact publicly resolvable
	src := Finding{
		Title: "Unauthenticated Prometheus metrics", Host: "https://h.example.com",
		DetectorID: "http.prometheus.public-metrics@1", Validation: "behavior-confirmed",
		Capabilities: []string{capAnonRead, capInternalHosts},
		Pivots:       []string{"internal_host=example.com"}, // resolves publicly
	}
	out := runPlanner(wd, "h.example.com", []Finding{src})
	found := false
	for _, f := range out {
		if strings.Contains(f.Title, "publicly resolvable") {
			found = true
			if f.Severity != "MEDIUM" {
				t.Errorf("pivot finding severity = %s, want MEDIUM", f.Severity)
			}
		}
	}
	if !found {
		t.Error("planner did not emit a publicly-resolvable pivot finding for a resolvable internal host")
	}
	edges := loadPlannerGraph(wd)
	if len(edges) == 0 {
		t.Error("planner did not persist any attack-graph edge")
	}
	sawResolve := false
	for _, e := range edges {
		if e.FromCap == capInternalHosts && strings.Contains(e.Result, "RESOLVES PUBLICLY") {
			sawResolve = true
		}
	}
	if !sawResolve {
		t.Error("no edge recorded the internal-host public resolution")
	}
}
