package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// M2/M3 — Runtime capability planner + persisted attack-graph edges.
// After a host's detectors emit findings (each carrying capabilities + pivots),
// the planner decides follow-up probes at RUNTIME and fires bounded,
// non-destructive checks. Every decision is persisted as an attack-graph edge
// (source capability -> decision -> probe -> resulting evidence/capability or
// an explicit STOP), so the narrative is execution accounting, not prose.

type PlannerEdge struct {
	Host        string `json:"host"`
	FromCap     string `json:"from_capability"`
	Decision    string `json:"decision"`
	Probe       string `json:"probe"`
	Result      string `json:"result"`
	Stop        string `json:"stop,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Timestamp   string `json:"timestamp"`
}

func plannerGraphPath(wd string) string { return filepath.Join(wd, "planner-graph.jsonl") }

func persistEdge(wd string, e PlannerEdge) {
	e.Timestamp = nowRFC()
	f, err := os.OpenFile(plannerGraphPath(wd), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	f.Write(append(b, '\n'))
}

func loadPlannerGraph(wd string) []PlannerEdge {
	b, err := os.ReadFile(plannerGraphPath(wd))
	if err != nil {
		return nil
	}
	var out []PlannerEdge
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e PlannerEdge
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// runPlanner consumes a host's findings and fires runtime follow-up probes based
// on the capabilities/pivots they emit. Returns any new findings; records every
// decision as an attack-graph edge. Bounded to one pivot round per host.
func runPlanner(wd, host string, findings []Finding) []Finding {
	var out []Finding
	// aggregate capabilities + pivots across this host's findings
	caps := map[string]bool{}
	var pivots []string
	techVersions := map[string]string{} // tech -> version (from fingerprint pivots)
	for i := range findings {
		f := &findings[i]
		cs := f.Capabilities
		if len(cs) == 0 {
			cs = capabilitiesFor(f)
		}
		for _, c := range cs {
			caps[c] = true
		}
		pivots = append(pivots, f.Pivots...)
		if v := pivotVersion(f); v != "" {
			techVersions[fpNameFromTitle(f.Title)] = v
		}
	}

	// Rule 1 — reveals_internal_hostnames -> resolve each internal name externally.
	// If an "internal" name actually resolves publicly, the disclosure became a
	// real, reachable pivot (surface expansion). This is genuine stateful chaining.
	if caps[capInternalHosts] {
		tested := 0
		for _, p := range pivots {
			if !strings.HasPrefix(p, "internal_host=") || tested >= 6 {
				continue
			}
			name := strings.TrimPrefix(p, "internal_host=")
			tested++
			addrs, err := net.LookupHost(name)
			if err != nil || len(addrs) == 0 {
				persistEdge(wd, PlannerEdge{Host: host, FromCap: capInternalHosts,
					Decision: "resolve disclosed internal hostname externally", Probe: "DNS A " + name,
					Result: "does not resolve from the external vantage", Stop: "STOP_NO_REACHABLE_TARGET"})
				continue
			}
			ev := captureEvidence(wd, "pivot.internal-host-reachable@1", host, "dns", "text/plain",
				"DNS A "+name, "none", []byte(name+" -> "+strings.Join(addrs, ", ")))
			out = append(out, Finding{
				Title: "Disclosed internal hostname is publicly resolvable: " + name, Host: "https://" + host, Severity: "MEDIUM",
				Status: "open", Confidence: "Confirmed", Validation: "behavior-confirmed",
				ObservedEvidence: fmt.Sprintf("An internal hostname disclosed by this host (%s) resolves publicly to %s. The disclosure is not merely informational — the named service is externally addressable, expanding the attack surface.", name, strings.Join(addrs, ", ")),
				ImpactText:       "A disclosed internal service name that resolves publicly can be targeted directly. Confirm the service should be internet-facing; if not, remove the public DNS record and the disclosure.",
				EvidenceCmd:      "dig +short " + shellQuote(name), ProbeKind: "manual", ProbeURL: "https://" + host,
				EvidenceRefs: []string{ev}, DetectorID: "pivot.internal-host-reachable@1",
				Capabilities: []string{capPublicService}, Pivots: []string{"resolved=" + name},
			})
			persistEdge(wd, PlannerEdge{Host: host, FromCap: capInternalHosts,
				Decision: "resolve disclosed internal hostname externally", Probe: "DNS A " + name,
				Result: "RESOLVES PUBLICLY -> new capability publicly_resolvable_service", EvidenceRef: ev})
		}
	}

	// Rule 2 — provides_service_version -> OSV CVE-applicability probe.
	for tech, ver := range techVersions {
		pkg, eco := techToOSV(tech)
		if pkg == "" {
			persistEdge(wd, PlannerEdge{Host: host, FromCap: capServiceVersion,
				Decision: "CVE applicability for " + tech + " " + ver, Probe: "OSV query",
				Result: "no OSV ecosystem mapping for this technology", Stop: "STOP_NO_PRIMITIVE"})
			continue
		}
		ids, maxSev := osvQuery(pkg, eco, ver)
		if len(ids) == 0 {
			persistEdge(wd, PlannerEdge{Host: host, FromCap: capServiceVersion,
				Decision: "CVE applicability for " + tech + " " + ver, Probe: "OSV " + pkg + "@" + ver,
				Result: "no known vulnerabilities affect this version", Stop: "STOP_NO_PRIMITIVE"})
			continue
		}
		ev := captureEvidence(wd, "component.banner-osv-correlation@1", host, "detector-parse", "application/json",
			"OSV "+pkg+"@"+ver, "none", []byte(strings.Join(ids, ", ")))
		out = append(out, Finding{
			Title: fmt.Sprintf("Potentially vulnerable %s %s (%d CVEs via OSV)", tech, ver, len(ids)),
			Host:  "https://" + host, Severity: capSev(maxSev), Status: "open",
			Confidence: "Low", Validation: "version-inferred", CVEs: capList(ids, 12),
			ObservedEvidence: fmt.Sprintf("Version %s of %s was fingerprinted; OSV reports %d advisories for this version (%s). Banner-inferred — confirm the exact build and feature exposure before scheduling emergency patching.", ver, tech, len(ids), strings.Join(capList(ids, 8), ", ")),
			ImpactText:       "Version-inferred CVE lead. Exploitability is not established; hiding the banner is not remediation. Validate applicability, then upgrade if genuinely affected.",
			EvidenceCmd:      "echo query OSV for " + pkg + "@" + ver, ProbeKind: "manual", ProbeURL: "https://" + host,
			EvidenceRefs: []string{ev}, DetectorID: "component.banner-osv-correlation@1", Capabilities: []string{capServiceVersion},
		})
		persistEdge(wd, PlannerEdge{Host: host, FromCap: capServiceVersion,
			Decision: "CVE applicability for " + tech + " " + ver, Probe: "OSV " + pkg + "@" + ver,
			Result: fmt.Sprintf("%d CVEs correlate (version-inferred)", len(ids)), Stop: "STOP_REQUIRES_AUTHORIZED_EXPLOIT", EvidenceRef: ev})
	}

	// Rule 3 — credential_material_candidate -> policy STOP (valuable evidence).
	if caps[capCredCandidate] {
		persistEdge(wd, PlannerEdge{Host: host, FromCap: capCredCandidate,
			Decision: "attempt to read/validate the credential-like value", Probe: "none",
			Result: "credential use is prohibited under adversarial-readonly", Stop: "STOP_POLICY_BOUNDARY"})
	}
	// Rule 4 — server_side_fetch already validated out-of-band; record the edge.
	if caps[capServerSideFetch] {
		persistEdge(wd, PlannerEdge{Host: host, FromCap: capServerSideFetch,
			Decision: "map reachable internal targets via SSRF", Probe: "OAST canary only",
			Result: "stopped at out-of-band interaction; no internal resource read", Stop: "STOP_POLICY_BOUNDARY"})
	}
	return out
}

// renderPlannerGraph renders the persisted attack-graph edges for the report.
func renderPlannerGraph(wd string) string {
	edges := loadPlannerGraph(wd)
	if len(edges) == 0 {
		return "_No runtime planner decisions were recorded (no capability-bearing findings triggered follow-up probes)._"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("The runtime planner recorded **%d attack-graph edge(s)** — each is a decision the engine made from a discovered capability, the probe it fired, and the result or explicit stop.\n\n", len(edges)))
	b.WriteString("| Host | From capability | Decision | Probe | Result | Stop |\n|---|---|---|---|---|---|\n")
	shown := edges
	if len(shown) > 40 {
		shown = shown[:40]
	}
	for _, e := range shown {
		b.WriteString(fmt.Sprintf("| %s | `%s` | %s | `%s` | %s | `%s` |\n",
			safeField(hostOf(e.Host)), e.FromCap, safeField(e.Decision), safeField(e.Probe), safeField(e.Result), orDash(e.Stop)))
	}
	if len(edges) > 40 {
		b.WriteString(fmt.Sprintf("\n_(+%d more edges in `planner-graph.jsonl`)_\n", len(edges)-40))
	}
	b.WriteString("\n_Edges are persisted append-only to `planner-graph.jsonl` and covered by the run's evidence-bundle hash._")
	return b.String()
}

// --- helpers ---------------------------------------------------------------

func pivotVersion(f *Finding) string {
	for _, p := range f.Pivots {
		if strings.HasPrefix(p, "version=") {
			return strings.TrimPrefix(p, "version=")
		}
	}
	return ""
}

// fpNameFromTitle extracts a technology name from a fingerprint finding title
// ("Operational service exposed: Grafana" -> "Grafana").
func fpNameFromTitle(title string) string {
	if i := strings.Index(title, ": "); i >= 0 {
		return strings.TrimSpace(title[i+2:])
	}
	return strings.TrimSpace(title)
}

// techToOSV maps a fingerprinted technology to an OSV package + ecosystem.
// Best-effort; extend as needed. Empty pkg = no mapping.
func techToOSV(tech string) (pkg, eco string) {
	switch strings.ToLower(tech) {
	case "grafana":
		return "grafana", "Go"
	case "gitlab":
		return "gitlab", "RubyGems"
	case "argo cd", "argocd":
		return "github.com/argoproj/argo-cd/v2", "Go"
	case "harbor":
		return "github.com/goharbor/harbor", "Go"
	case "minio":
		return "github.com/minio/minio", "Go"
	case "hashicorp consul", "consul":
		return "github.com/hashicorp/consul", "Go"
	case "hashicorp vault", "vault":
		return "github.com/hashicorp/vault", "Go"
	case "jenkins":
		return "jenkins", "Maven"
	case "elasticsearch":
		return "org.elasticsearch:elasticsearch", "Maven"
	}
	return "", ""
}

func capSev(maxSev int) string {
	// version-inferred leads are capped at MEDIUM regardless of nominal CVE severity
	if maxSev >= 3 {
		return "MEDIUM"
	}
	return "LOW"
}
