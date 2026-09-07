package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Capability vocabulary — what an attacker gains from a finding. The attack graph
// reasons over these, so a finding is a source of capabilities, not just a
// severity. This is what turns independent observations into tested attack paths.
const (
	capAnonRead        = "anonymous_read"
	capInternalHosts   = "reveals_internal_hostnames"
	capServiceVersion  = "provides_service_version"
	capServerSideFetch = "server_side_fetch"
	capCredCandidate   = "credential_material_candidate"
	capAuthBoundary    = "auth_boundary"
	capTakeover        = "takeover_candidate"
	capRedirect        = "redirect_primitive"
	capPublicService   = "publicly_resolvable_service"
)

var reInternalName = regexp.MustCompile(`(?i)[a-z0-9_.-]+\.(internal|local|svc|cluster\.local|intranet|corp)\b`)
var reNamespace = regexp.MustCompile(`(?i)(namespace|pod|kube[a-z_]*)="?([a-z0-9-]+)`)
var reVersionTok = regexp.MustCompile(`(?i)(version|build)[="_ ]+v?(\d+\.\d+[\.\d]*)`)

// capabilitiesFor derives the capabilities a finding grants, and extractPivots
// pulls concrete pivot intelligence from its evidence.
func capabilitiesFor(f *Finding) []string {
	var caps []string
	ev := strings.ToLower(f.ObservedEvidence)
	add := func(c string) {
		if !contains(caps, c) {
			caps = append(caps, c)
		}
	}
	switch findingType(f) {
	case "metrics-exposed":
		add(capAnonRead)
		if strings.Contains(ev, "[x] internal hostname") {
			add(capInternalHosts)
		}
		if strings.Contains(ev, "[x] service/version") {
			add(capServiceVersion)
		}
		if strings.Contains(ev, "[x] credential") {
			add(capCredCandidate)
		}
	case "exposure-path":
		add(capAnonRead)
		add(capInternalHosts)
	case "component-lead":
		add(capServiceVersion)
	case "cors":
		add(capAuthBoundary)
	}
	switch detectorOf(f) {
	case "identity.oidc-surface@1":
		add(capAuthBoundary)
	case "api.schema-exposure@1":
		add(capAnonRead)
	case "storage.public-bucket@1":
		add(capAnonRead)
	case "tech.service-fingerprint@1":
		add(capServiceVersion)
	case "dns.dangling-cname@1":
		add(capTakeover)
	case "http.open-redirect@1":
		add(capRedirect)
	case "http.ssrf@1", "api.ssrf@1":
		add(capServerSideFetch)
	}
	sort.Strings(caps)
	return caps
}

// extractPivots pulls internal hostnames, namespaces and versions from evidence
// (e.g. a Prometheus body) so an exposure becomes a pivot source, not a dead-end.
func extractPivots(body string) []string {
	var pivots []string
	seen := map[string]bool{}
	add := func(kind, v string) {
		key := kind + ":" + v
		if v != "" && !seen[key] {
			seen[key] = true
			pivots = append(pivots, kind+"="+v)
		}
	}
	for _, m := range reInternalName.FindAllString(body, 8) {
		add("internal_host", strings.ToLower(m))
	}
	for _, m := range reNamespace.FindAllStringSubmatch(body, 8) {
		add("namespace", strings.ToLower(m[2]))
	}
	for _, m := range reVersionTok.FindAllStringSubmatch(body, 6) {
		add("version", m[2])
	}
	if len(pivots) > 12 {
		pivots = pivots[:12]
	}
	return pivots
}

// pivotSummary renders extracted pivots for a finding.
func pivotSummary(f *Finding) string {
	if len(f.Pivots) == 0 {
		return ""
	}
	return fmt.Sprintf("Pivot intelligence extracted: %s", strings.Join(f.Pivots, "; "))
}
