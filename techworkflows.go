package main

import (
	"fmt"
	"strings"
)

// v0.30 — Technology-specific adversarial mini-workflows.
// A fingerprinted service triggers an ordered pivot tree: each step is a bounded,
// GET-only decision recorded as a planner attack-graph edge at increasing depth,
// so one discovery produces 2-5 intelligent follow-ups instead of a single
// generic probe. Workflows stop at the adversarial-readonly proof boundary.

// wfStep is one decision in a workflow: a probe that returns a human result, an
// optional terminal stop code, and an optional finding to surface.
type wfStep struct {
	cap      string
	decision string
	run      func(base string) (result, stop string, f *Finding)
}

// techWorkflowFor returns the ordered workflow for a fingerprinted technology
// name (matched by lowercased substring), or nil if none is registered.
func techWorkflowFor(name string) []wfStep {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "minio"), strings.Contains(n, "s3"), strings.Contains(n, "object stor"):
		return objectStoreWorkflow()
	case strings.Contains(n, "harbor"):
		return harborWorkflow()
	case strings.Contains(n, "kong"):
		return kongWorkflow()
	case strings.Contains(n, "grafana"):
		return grafanaWorkflow()
	case strings.Contains(n, "elasticsearch"):
		return elasticWorkflow()
	case strings.Contains(n, "vault"):
		return vaultWorkflow()
	}
	return nil
}

// runTechWorkflow executes a workflow, recording each step as a planner edge at
// the given depth (+step offset) and collecting any findings.
func runTechWorkflow(wd, host, base, tech string, steps []wfStep, depth int) []Finding {
	var out []Finding
	for i, s := range steps {
		result, stop, f := s.run(base)
		persistEdge(wd, PlannerEdge{Host: host, Depth: depth + i, FromCap: s.cap,
			Decision: tech + ": " + s.decision, Probe: "GET " + base, Result: result, Stop: stop})
		if f != nil {
			out = append(out, *f)
		}
		if stop == "STOP_NO_REACHABLE_TARGET" {
			break // the service did not answer; later steps are moot
		}
	}
	return out
}

// --- per-technology workflows ----------------------------------------------

func objectStoreWorkflow() []wfStep {
	return []wfStep{
		{capAnonRead, "anonymous ListBuckets at the store root", func(base string) (string, string, *Finding) {
			code, _, body, ok := getWithBody(joinBase(base, "/"), 32*1024)
			if ok && code == 200 && (strings.Contains(body, "<ListBucketResult") || strings.Contains(body, "<ListAllMyBucketsResult")) {
				return "anonymous bucket listing confirmed", "", nil
			}
			return "root listing not anonymous (HTTP " + itoa(code) + ")", "STOP_NO_PRIMITIVE", nil
		}},
		{capAnonRead, "probe anonymous object read on a benign well-known key", func(base string) (string, string, *Finding) {
			code, _, _, _ := getWithBody(joinBase(base, "/health"), 2048)
			return fmt.Sprintf("benign key probe returned HTTP %d; object downloads not attempted", code), "STOP_POLICY_BOUNDARY", nil
		}},
		{capAuthBoundary, "check cross-origin policy on the store", func(base string) (string, string, *Finding) {
			refl, creds, ok := corsOriginMatrix(joinBase(base, "/"))
			if ok && refl {
				return fmt.Sprintf("reflects arbitrary Origin (credentials=%v)", creds), "", nil
			}
			return "no arbitrary-origin reflection", "STOP_NO_PRIMITIVE", nil
		}},
	}
}

func harborWorkflow() []wfStep {
	return []wfStep{
		{capAnonRead, "anonymous registry catalog (/v2/_catalog)", func(base string) (string, string, *Finding) {
			code, _, body, ok := getWithBody(joinBase(base, "/v2/_catalog"), 16*1024)
			if ok && code == 200 && strings.Contains(body, "repositories") {
				return "anonymous catalog readable — image names enumerable", "", nil
			}
			return "catalog not anonymous (HTTP " + itoa(code) + ")", "STOP_NO_PRIMITIVE", nil
		}},
		{capServiceVersion, "read system info / version (/api/v2.0/systeminfo)", func(base string) (string, string, *Finding) {
			code, _, body, _ := getWithBody(joinBase(base, "/api/v2.0/systeminfo"), 16*1024)
			if code == 200 && strings.Contains(body, "harbor_version") {
				return "systeminfo exposes harbor_version (feeds CVE applicability)", "STOP_REQUIRES_AUTHORIZED_EXPLOIT", nil
			}
			return fmt.Sprintf("systeminfo HTTP %d", code), "STOP_NO_PRIMITIVE", nil
		}},
	}
}

func kongWorkflow() []wfStep {
	return []wfStep{
		{capAnonRead, "distinguish proxy vs admin API and probe /status", func(base string) (string, string, *Finding) {
			code, _, body, _ := getWithBody(joinBase(base, "/status"), 8192)
			if code == 200 && strings.Contains(body, "database") {
				return "Kong admin /status reachable unauthenticated (admin API exposed)", "", &Finding{
					Title: "Kong admin API exposed (/status)", Host: base, Severity: "HIGH", Status: "open",
					Confidence: "Confirmed", Validation: "behavior-confirmed",
					ObservedEvidence: "GET /status returned Kong admin status unauthenticated — the admin API controls routing/auth and must never be public.",
					ImpactText:       "An exposed Kong admin API lets an attacker reconfigure routes, plugins and auth. Restrict the admin API to localhost/mTLS.",
					ProbeKind:        "status", ProbeURL: joinBase(base, "/status"), DetectorID: "tech.second-stage@1",
					Capabilities: []string{capAuthBoundary},
				}
			}
			return fmt.Sprintf("/status HTTP %d (admin API not exposed here)", code), "STOP_NO_PRIMITIVE", nil
		}},
	}
}

func grafanaWorkflow() []wfStep {
	return []wfStep{
		{capServiceVersion, "read /api/health for version", func(base string) (string, string, *Finding) {
			code, _, body, _ := getWithBody(joinBase(base, "/api/health"), 8192)
			if code == 200 && strings.Contains(body, "version") {
				return "/api/health exposes Grafana version (feeds CVE applicability)", "STOP_REQUIRES_AUTHORIZED_EXPLOIT", nil
			}
			return fmt.Sprintf("/api/health HTTP %d", code), "STOP_NO_PRIMITIVE", nil
		}},
		{capAuthBoundary, "probe anonymous org access (/api/org)", func(base string) (string, string, *Finding) {
			code, _, _, _ := getWithBody(joinBase(base, "/api/org"), 8192)
			if code == 200 {
				return "anonymous org access enabled (/api/org readable)", "", &Finding{
					Title: "Grafana anonymous organization access", Host: base, Severity: "MEDIUM", Status: "open",
					Confidence: "Confirmed", Validation: "behavior-confirmed",
					ObservedEvidence: "GET /api/org returned 200 unauthenticated — anonymous access is enabled.",
					ImpactText:       "Anonymous Grafana access can expose dashboards, datasource names and internal metrics. Disable anonymous auth.",
					ProbeKind:        "status", ProbeURL: joinBase(base, "/api/org"), DetectorID: "tech.second-stage@1",
					Capabilities: []string{capAnonRead},
				}
			}
			return fmt.Sprintf("/api/org HTTP %d (anonymous access off)", code), "STOP_NO_PRIMITIVE", nil
		}},
	}
}

func elasticWorkflow() []wfStep {
	return []wfStep{
		{capAnonRead, "anonymous cluster info (/)", func(base string) (string, string, *Finding) {
			code, _, body, _ := getWithBody(joinBase(base, "/"), 16*1024)
			if code == 200 && strings.Contains(body, "cluster_name") {
				return "cluster info readable anonymously (version + cluster name)", "", nil
			}
			return fmt.Sprintf("/ HTTP %d", code), "STOP_NO_PRIMITIVE", nil
		}},
		{capAnonRead, "anonymous index listing (/_cat/indices)", func(base string) (string, string, *Finding) {
			code, _, body, _ := getWithBody(joinBase(base, "/_cat/indices"), 16*1024)
			if code == 200 && !strings.Contains(body, "security_exception") && len(strings.TrimSpace(body)) > 0 {
				return "indices enumerable anonymously — data likely readable", "STOP_POLICY_BOUNDARY", nil
			}
			return fmt.Sprintf("/_cat/indices HTTP %d (gated)", code), "STOP_NO_PRIMITIVE", nil
		}},
	}
}

func vaultWorkflow() []wfStep {
	return []wfStep{
		{capServiceVersion, "read seal status (/v1/sys/seal-status)", func(base string) (string, string, *Finding) {
			code, _, body, _ := getWithBody(joinBase(base, "/v1/sys/seal-status"), 8192)
			if code == 200 && strings.Contains(body, "version") {
				return "seal-status discloses version + seal state (operational intel)", "STOP_REQUIRES_AUTHORIZED_EXPLOIT", nil
			}
			return fmt.Sprintf("/v1/sys/seal-status HTTP %d", code), "STOP_NO_PRIMITIVE", nil
		}},
	}
}
