package exposure

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/jsonl"
)

func atoiSafe(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

// LoadLeaks reads leaks.jsonl, or nil.
func LoadLeaks(path string) []LeakFinding {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []LeakFinding
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var f LeakFinding
		if jsonl.JSONUnmarshalLine(ln, &f) {
			out = append(out, f)
		}
	}
	return out
}

// hostPorts groups observations into a per-host port/service map.
func hostPorts(obs []Observation) map[string][]Observation {
	m := map[string][]Observation{}
	for _, o := range obs {
		m[o.IP] = append(m[o.IP], o)
	}
	for ip := range m {
		sort.Slice(m[ip], func(i, j int) bool { return m[ip][i].Port < m[ip][j].Port })
	}
	return m
}

// DatastorePorts are services that must not be internet-reachable; their mere
// exposure is a finding regardless of version (defense in depth).
var DatastorePorts = map[string]bool{
	"mysql": true, "postgresql": true, "redis": true, "mongodb": true,
	"elasticsearch": true, "rdp": true,
}

// LoadDBChecks reads dbcheck.jsonl, or nil.
func LoadDBChecks(path string) []DBResult {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []DBResult
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var r DBResult
		if jsonl.JSONUnmarshalLine(ln, &r) {
			out = append(out, r)
		}
	}
	return out
}

// LoadCandidates reads candidates.jsonl, or nil.
func LoadCandidates(path string) []intel.Candidate {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []intel.Candidate
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var c intel.Candidate
		if jsonl.JSONUnmarshalLine(ln, &c) {
			out = append(out, c)
		}
	}
	return out
}

// svcTally renders service counts, largest first, ties by name.
func svcTally(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool {
		if s[i].v != s[j].v {
			return s[i].v > s[j].v
		}
		return s[i].k < s[j].k // ties: stable by name
	})
	var parts []string
	for _, e := range s {
		parts = append(parts, fmt.Sprintf("%s %d", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 4 || len(pb) != 4 {
		return a < b
	}
	for i := 0; i < 4; i++ {
		x, y := atoiSafe(pa[i]), atoiSafe(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}
