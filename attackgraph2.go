package main

import (
	"fmt"
	"sort"
	"strings"
)

// Attack-graph reasoning. Each finding contributes capabilities; the engine
// derives candidate attack paths from capability preconditions, records how far
// each advanced, and reports the exploration explicitly — so the narrative
// emerges from execution accounting, not prose synthesis.

type attackPath struct {
	name       string
	precond    string   // capability that opens the path
	steps      []string // narrative steps
	advanced   bool     // a second capability/discovery extended it
	validated  bool     // a safe primitive confirmed an intermediate step
	boundary   string   // why it stops (proof boundary)
}

// pathTemplates define the candidate attack paths the engine reasons about.
var pathTemplates = []struct {
	name     string
	precond  string
	extendBy []string // capabilities that "advance" the path
	validatedBy []string // capabilities that mark a validated primitive
	boundary string
}{
	{"Internal-topology reconnaissance", capInternalHosts, []string{capServiceVersion, capPublicService}, []string{},
		"Stops at disclosure; internal hosts are not routable from the external vantage and no exfiltration is attempted."},
	{"Version-to-CVE applicability", capServiceVersion, []string{capInternalHosts}, []string{},
		"Stops at a version-inferred lead; CVE exploitation is out of scope (requires authorized-exploit)."},
	{"Anonymous-read data exposure", capAnonRead, []string{capCredCandidate, capInternalHosts}, []string{capCredCandidate},
		"Stops at reading benign/enumerable content; no secret extraction is attempted."},
	{"Credential-material acquisition", capCredCandidate, []string{capAnonRead}, []string{},
		"Stops at an unvalidated credential-like pattern; secrets are neither confirmed nor used."},
	{"Server-side request forgery", capServerSideFetch, []string{}, []string{capServerSideFetch},
		"Validated only via an out-of-band OAST callback to our canary; no internal resource is read."},
	{"Subdomain takeover", capTakeover, []string{}, []string{},
		"Stops at a takeover candidate; provider claimability is not exercised."},
	{"Open-redirect abuse", capRedirect, []string{}, []string{capRedirect},
		"Validated by observing the redirect to a canary; no victim interaction is involved."},
	{"Authorization-boundary bypass", capAuthBoundary, []string{}, []string{},
		"Stops after read-only bypass variants; no credentials are attempted."},
}

// buildAttackGraph accumulates capabilities across findings and evaluates each
// candidate path.
func buildAttackGraph(findings []Finding) []attackPath {
	present := map[string]int{} // capability -> count of findings providing it
	validatedCap := map[string]bool{}
	for i := range findings {
		f := &findings[i]
		caps := f.Capabilities
		if len(caps) == 0 {
			caps = capabilitiesFor(f)
		}
		for _, c := range caps {
			present[c]++
			// a behavior-confirmed finding validates its capability as real
			if f.Validation == "behavior-confirmed" || f.Validation == "exploited" {
				validatedCap[c] = true
			}
		}
	}
	var paths []attackPath
	for _, t := range pathTemplates {
		if present[t.precond] == 0 {
			continue
		}
		p := attackPath{name: t.name, precond: t.precond, boundary: t.boundary,
			steps: []string{"initial capability: " + t.precond}}
		for _, e := range t.extendBy {
			if present[e] > 0 {
				p.advanced = true
				p.steps = append(p.steps, "advanced via: "+e)
			}
		}
		for _, v := range t.validatedBy {
			if validatedCap[v] {
				p.validated = true
				p.steps = append(p.steps, "validated primitive: "+v)
			}
		}
		paths = append(paths, p)
	}
	return paths
}

// renderAttackGraph produces the adversarial narrative + exploration accounting.
func renderAttackGraph(findings []Finding, profile Profile) string {
	paths := buildAttackGraph(findings)
	explored := len(paths)
	advanced, validated := 0, 0
	for _, p := range paths {
		if p.advanced {
			advanced++
		}
		if p.validated {
			validated++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**Aggression profile:** %s\n\n", profile.String())
	if explored == 0 {
		b.WriteString("No capability-bearing findings were observed, so no candidate attack paths were opened.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "The engine explored **%d candidate attack path(s)**, advanced **%d** beyond initial discovery, and validated **%d** intermediate primitive(s). No path reached the defined impact boundary (no state change, no data exfiltration, no credential use).\n\n",
		explored, advanced, validated)
	// order: validated first, then advanced, then the rest
	sort.SliceStable(paths, func(i, j int) bool {
		score := func(p attackPath) int {
			s := 0
			if p.validated {
				s += 2
			}
			if p.advanced {
				s++
			}
			return s
		}
		return score(paths[i]) > score(paths[j])
	})
	b.WriteString("| Attack path | Opened by | Advanced | Validated | Proof boundary |\n|---|---|:--:|:--:|---|\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s |\n", p.name, p.precond, yesno(p.advanced), yesno(p.validated), p.boundary)
	}
	b.WriteString("\n_Paths are derived from the capabilities each finding grants (capability model), not from prose. A path \"advances\" when a second capability extends it and \"validates\" when a harmless primitive (OAST callback, redirect-to-canary, arithmetic SSTI) confirms an intermediate step._")
	return b.String()
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "—"
}
