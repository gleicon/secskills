package main

import (
	"fmt"
	"strings"
)

// Technology-triggered second-stage packs.
// Discovery should deepen testing dynamically: a fingerprinted service triggers
// its own bounded, GET-only anonymous checks instead of stopping at "exposed".
// Packs are a registry keyed by a fingerprint substring, so adding a technology
// is data, not new control flow.

type ssPack struct {
	// trigger matches (lower-cased) against the fingerprint title.
	trigger string
	// probe runs GET-only anonymous checks and returns any findings.
	probe func(wd, base string) []Finding
}

// secondStageRegistry is the ordered list of technology packs. Extend this to add
// a technology; nothing else changes.
func secondStageRegistry() []ssPack {
	return []ssPack{
		{"minio", ssObjectStore},
		{"s3", ssObjectStore},
		{"elasticsearch", ssElasticsearch},
		{"kibana", ssHTTPPaths("Kibana", "LOW", []string{"/api/status", "/app/kibana"}, "kibana")},
		{"grafana", ssHTTPPaths("Grafana", "LOW", []string{"/api/health", "/login"}, "grafana")},
		{"vault", ssJSONPaths("HashiCorp Vault", []string{"/v1/sys/health", "/v1/sys/seal-status"})},
		{"consul", ssConsul},
		{"argo", ssHTTPPaths("Argo CD", "LOW", []string{"/api/version", "/api/v1/applications"}, "argo")},
		{"harbor", ssHarbor},
		{"kubernetes", ssHTTPPaths("Kubernetes Dashboard", "MEDIUM", []string{"/api/v1/namespaces", "/api/v1/pods"}, "items")},
		{"gitlab", ssHTTPPaths("GitLab", "LOW", []string{"/explore", "/users/sign_in"}, "gitlab")},
		{"jenkins", ssHTTPPaths("Jenkins", "MEDIUM", []string{"/api/json", "/whoAmI"}, "jenkins")},
	}
}

// runSecondStage dispatches to every pack whose trigger matches the fingerprint.
func runSecondStage(wd, base, fpTitle string) []Finding {
	low := strings.ToLower(fpTitle)
	var out []Finding
	seen := map[string]bool{}
	for _, p := range secondStageRegistry() {
		if seen[p.trigger] || !strings.Contains(low, p.trigger) {
			continue
		}
		seen[p.trigger] = true
		out = append(out, p.probe(wd, base)...)
	}
	return out
}

// --- generic pack builders --------------------------------------------------

// ssHTTPPaths builds a pack that flags a service path reachable unauthenticated
// when the response is 200 and contains `sig` (or sig is empty).
func ssHTTPPaths(service, sev string, paths []string, sig string) func(wd, base string) []Finding {
	return func(wd, base string) []Finding {
		var out []Finding
		for _, p := range paths {
			u := strings.TrimRight(base, "/") + p
			code, _, body, ok := getWithBody(u, 16*1024)
			if !ok || code != 200 {
				continue
			}
			if sig != "" && !strings.Contains(strings.ToLower(body), sig) {
				continue
			}
			ev := captureEvidence(wd, "tech.second-stage@1", base, "http-response", "text/plain", "GET "+u, "redacted",
				[]byte(fmt.Sprintf("HTTP %d at %s (%s)", code, p, service)))
			out = append(out, Finding{
				Title: service + " endpoint reachable unauthenticated (" + p + ")", Host: u, Severity: sev, Status: "open",
				Confidence: "Confirmed", Validation: "behavior-confirmed",
				ObservedEvidence: fmt.Sprintf("GET %s returned HTTP %d — the %s surface answers unauthenticated.", u, code, service),
				ImpactText:       "An exposed " + service + " endpoint widens the attack surface (enumeration, version CVEs, potential unauthenticated data). Restrict to trusted networks / require authentication.",
				EvidenceCmd:      "curl -skI " + shellQuote(u), ProbeKind: "status", ProbeURL: u,
				EvidenceRefs:     []string{ev}, DetectorID: "tech.second-stage@1", Capabilities: []string{capServiceVersion},
			})
			break // one hit per service is enough
		}
		return out
	}
}

// ssJSONPaths flags a service whose JSON status/health API answers anonymously.
func ssJSONPaths(service string, paths []string) func(wd, base string) []Finding {
	return func(wd, base string) []Finding {
		var out []Finding
		for _, p := range paths {
			u := strings.TrimRight(base, "/") + p
			code, hdr, body, ok := getWithBody(u, 16*1024)
			if !ok || code != 200 || !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "json") {
				continue
			}
			ev := captureEvidence(wd, "tech.second-stage@1", base, "http-response", "application/json", "GET "+u, "redacted",
				[]byte(body[:min(len(body), 4096)]))
			out = append(out, Finding{
				Title: service + " status API reachable unauthenticated (" + p + ")", Host: u, Severity: "MEDIUM", Status: "open",
				Confidence: "Confirmed", Validation: "behavior-confirmed",
				ObservedEvidence: fmt.Sprintf("GET %s returned HTTP 200 JSON — the %s status/health API answers unauthenticated.", u, service),
				ImpactText:       "The " + service + " status API discloses operational state (seal/health/version) that aids targeting. Require authentication / network restriction.",
				EvidenceCmd:      "curl -sk " + shellQuote(u), ProbeKind: "status", ProbeURL: u,
				EvidenceRefs:     []string{ev}, DetectorID: "tech.second-stage@1", Capabilities: []string{capServiceVersion, capInternalHosts},
			})
			break
		}
		return out
	}
}

// --- service-specific packs -------------------------------------------------

// ssObjectStore covers S3-compatible object stores (MinIO and similar): anonymous
// root listing plus console/health surface. GET-only; never attempts writes.
func ssObjectStore(wd, base string) []Finding {
	var out []Finding
	if code, _, body, ok := getWithBody(strings.TrimRight(base, "/")+"/", 32*1024); ok && code == 200 &&
		(strings.Contains(body, "<ListAllMyBucketsResult") || strings.Contains(body, "<ListBucketResult")) {
		ev := captureEvidence(wd, "storage.public-bucket@1", base, "http-response", "application/xml", "GET "+base+"/", "redacted", []byte(body[:min(len(body), 8192)]))
		out = append(out, Finding{
			Title: "Object store anonymous bucket listing", Host: base, Severity: "HIGH", Status: "open",
			Confidence: "Confirmed", Validation: "behavior-confirmed",
			ObservedEvidence: "Anonymous GET on the object-store root returned an S3 ListBuckets/ListBucket XML response — buckets/objects are enumerable unauthenticated.",
			ImpactText:       "Anonymous listing discloses bucket and object names and may expose object contents. Require authentication; disable anonymous policy.",
			EvidenceCmd:      "curl -sk " + shellQuote(base) + "/", ProbeKind: "body-contains", ProbeURL: base + "/", ProbeArg: "<List",
			EvidenceRefs:     []string{ev}, DetectorID: "storage.public-bucket@1", Capabilities: []string{capAnonRead},
		})
	}
	for _, p := range []string{"/minio/health/live", "/minio/", "/minio/login"} {
		u := strings.TrimRight(base, "/") + p
		if code, _, body, ok := getWithBody(u, 8*1024); ok && code == 200 &&
			(p == "/minio/health/live" || strings.Contains(strings.ToLower(body), "minio")) {
			ev := captureEvidence(wd, "tech.second-stage@1", base, "http-response", "text/plain", "GET "+u, "none", []byte(fmt.Sprintf("HTTP %d at %s", code, p)))
			out = append(out, Finding{
				Title: "Object-store console/health endpoint reachable (" + p + ")", Host: u, Severity: "LOW", Status: "open",
				Confidence: "Confirmed", Validation: "behavior-confirmed",
				ObservedEvidence: fmt.Sprintf("GET %s returned HTTP %d — the object-store console/health surface is reachable unauthenticated.", u, code),
				ImpactText:       "An exposed console widens the attack surface (login brute-force, version CVEs). Restrict to trusted networks.",
				EvidenceCmd:      "curl -skI " + shellQuote(u), ProbeKind: "status", ProbeURL: u,
				EvidenceRefs:     []string{ev}, DetectorID: "tech.second-stage@1", Capabilities: []string{capServiceVersion},
			})
			break
		}
	}
	return out
}

// ssElasticsearch: anonymous cluster info + index listing.
func ssElasticsearch(wd, base string) []Finding {
	var out []Finding
	if code, _, body, ok := getWithBody(strings.TrimRight(base, "/")+"/_cat/indices", 32*1024); ok && code == 200 && len(strings.TrimSpace(body)) > 0 && !strings.Contains(body, "security_exception") {
		ev := captureEvidence(wd, "tech.second-stage@1", base, "http-response", "text/plain", "GET "+base+"/_cat/indices", "redacted", []byte(body[:min(len(body), 8192)]))
		out = append(out, Finding{
			Title: "Elasticsearch anonymous index listing (/_cat/indices)", Host: base, Severity: "HIGH", Status: "open",
			Confidence: "Confirmed", Validation: "behavior-confirmed",
			ObservedEvidence: "GET /_cat/indices returned an index listing unauthenticated — data indices are enumerable and likely readable.",
			ImpactText:       "Anonymous Elasticsearch access exposes indexed data (often PII/logs) to anyone. Enable authentication (X-Pack/OpenSearch security) and restrict network access.",
			EvidenceCmd:      "curl -sk " + shellQuote(base) + "/_cat/indices", ProbeKind: "status", ProbeURL: base + "/_cat/indices",
			EvidenceRefs:     []string{ev}, DetectorID: "tech.second-stage@1", Capabilities: []string{capAnonRead, capInternalHosts},
		})
	}
	return out
}

// ssConsul: anonymous service catalog.
func ssConsul(wd, base string) []Finding {
	u := strings.TrimRight(base, "/") + "/v1/catalog/services"
	code, hdr, body, ok := getWithBody(u, 16*1024)
	if !ok || code != 200 || !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "json") {
		return nil
	}
	ev := captureEvidence(wd, "tech.second-stage@1", base, "http-response", "application/json", "GET "+u, "redacted", []byte(body[:min(len(body), 4096)]))
	return []Finding{{
		Title: "Consul anonymous service catalog (/v1/catalog/services)", Host: u, Severity: "HIGH", Status: "open",
		Confidence: "Confirmed", Validation: "behavior-confirmed",
		ObservedEvidence: "GET /v1/catalog/services returned the service catalog unauthenticated — internal service topology is disclosed.",
		ImpactText:       "Anonymous Consul access discloses (and can modify, with write ACLs) service registration and KV data. Enable ACLs with default-deny and restrict the HTTP API.",
		EvidenceCmd:      "curl -sk " + shellQuote(u), ProbeKind: "status", ProbeURL: u,
		EvidenceRefs:     []string{ev}, DetectorID: "tech.second-stage@1", Capabilities: []string{capInternalHosts, capAnonRead},
	}}
}

// ssHarbor: anonymous registry catalog + system info.
func ssHarbor(wd, base string) []Finding {
	var out []Finding
	if code, _, body, ok := getWithBody(strings.TrimRight(base, "/")+"/v2/_catalog", 16*1024); ok && code == 200 && strings.Contains(body, "repositories") {
		ev := captureEvidence(wd, "tech.second-stage@1", base, "http-response", "application/json", "GET "+base+"/v2/_catalog", "redacted", []byte(body[:min(len(body), 4096)]))
		out = append(out, Finding{
			Title: "Container registry anonymous catalog (/v2/_catalog)", Host: base, Severity: "HIGH", Status: "open",
			Confidence: "Confirmed", Validation: "behavior-confirmed",
			ObservedEvidence: "GET /v2/_catalog returned the repository catalog unauthenticated — image names (and often layers) are enumerable.",
			ImpactText:       "Anonymous registry access exposes internal image names and may allow pulling images containing secrets/source. Require authentication on the registry.",
			EvidenceCmd:      "curl -sk " + shellQuote(base) + "/v2/_catalog", ProbeKind: "body-contains", ProbeURL: base + "/v2/_catalog", ProbeArg: "repositories",
			EvidenceRefs:     []string{ev}, DetectorID: "tech.second-stage@1", Capabilities: []string{capAnonRead, capInternalHosts},
		})
	}
	return out
}
