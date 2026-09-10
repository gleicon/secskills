package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// M4 — Real adversarial-module instrumentation.
// Each active module records candidates probed / positives / inconclusive as it
// runs, so the Adversarial Control Ledger reports measured denominators instead
// of a derived approximation. Per-process (one target per run); reset at start.

type advCounter struct {
	Candidates   int `json:"candidates"`
	Positive     int `json:"positive"`
	Inconclusive int `json:"inconclusive"`
}

var (
	advMu    sync.Mutex
	advStats = map[string]*advCounter{}
)

func advReset() {
	advMu.Lock()
	advStats = map[string]*advCounter{}
	advMu.Unlock()
}

func advc(module string) *advCounter {
	if advStats[module] == nil {
		advStats[module] = &advCounter{}
	}
	return advStats[module]
}

// advProbe records n candidate probes attempted by a module.
func advProbe(module string, n int) {
	advMu.Lock()
	advc(module).Candidates += n
	advMu.Unlock()
}

// advHit records a positive finding from a module.
func advHit(module string) {
	advMu.Lock()
	advc(module).Positive++
	advMu.Unlock()
}

// advInconc records an inconclusive result from a module.
func advInconc(module string) {
	advMu.Lock()
	advc(module).Inconclusive++
	advMu.Unlock()
}

func advStatsPath(wd string) string { return filepath.Join(wd, "adv-stats.json") }

func writeAdvStats(wd string) {
	advMu.Lock()
	defer advMu.Unlock()
	b, _ := json.MarshalIndent(advStats, "", "  ")
	os.WriteFile(advStatsPath(wd), b, 0o644)
}

func loadAdvStats(wd string) map[string]advCounter {
	b, err := os.ReadFile(advStatsPath(wd))
	if err != nil {
		return nil
	}
	var m map[string]advCounter
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

// renderMeasuredLedger renders the adversarial ledger from measured counters.
// Returns "" when no stats were recorded (caller falls back to the derived view).
func renderMeasuredLedger(wd string) string {
	stats := loadAdvStats(wd)
	if len(stats) == 0 {
		return ""
	}
	mods := make([]string, 0, len(stats))
	for k := range stats {
		mods = append(mods, k)
	}
	sort.Strings(mods)
	var b strings.Builder
	b.WriteString("| Adversarial module | Probe attempts | Positive | Inconclusive |\n|---|--:|--:|--:|\n")
	var tc, tp, ti int
	for _, m := range mods {
		c := stats[m]
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d |\n", m, c.Candidates, c.Positive, c.Inconclusive))
		tc, tp, ti = tc+c.Candidates, tp+c.Positive, ti+c.Inconclusive
	}
	b.WriteString(fmt.Sprintf("| **Total** | **%d** | **%d** | **%d** |\n", tc, tp, ti))
	b.WriteString("\n_Measured per-probe during the run (not derived): Candidates = actual probe attempts; Positive = confirmed findings; a zero positive against a non-zero candidate count is a real negative result. Persisted to `adv-stats.json` (in the evidence bundle)._")
	return b.String()
}
