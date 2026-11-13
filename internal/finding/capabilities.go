package finding

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/textutil"
)

// Capability vocabulary — what an attacker gains from a finding. The attack graph
// reasons over these, so a finding is a source of capabilities, not just a
// severity. This is what turns independent observations into tested attack paths.
const (
	CapAnonRead        = "anonymous_read"
	CapInternalHosts   = "reveals_internal_hostnames"
	CapServiceVersion  = "provides_service_version"
	CapServerSideFetch = "server_side_fetch"
	CapCredCandidate   = "credential_material_candidate"
	CapAuthBoundary    = "auth_boundary"
	CapTakeover        = "takeover_candidate"
	CapRedirect        = "redirect_primitive"
	CapPublicService   = "publicly_resolvable_service"
)

var reInternalName = regexp.MustCompile(`(?i)[a-z0-9_.-]+\.(internal|local|svc|cluster\.local|intranet|corp)\b`)
var reNamespace = regexp.MustCompile(`(?i)(namespace|pod|kube[a-z_]*)="?([a-z0-9-]+)`)
var reVersionTok = regexp.MustCompile(`(?i)(version|build)[="_ ]+v?(\d+\.\d+[\.\d]*)`)

// CapabilitiesFor derives the capabilities a finding grants, and extractPivots
// pulls concrete pivot intelligence from its evidence.
func CapabilitiesFor(f *Finding) []string {
	var caps []string
	ev := strings.ToLower(f.ObservedEvidence)
	add := func(c string) {
		if !textutil.Contains(caps, c) {
			caps = append(caps, c)
		}
	}
	switch FindingType(f) {
	case "metrics-exposed":
		add(CapAnonRead)
		if strings.Contains(ev, "[x] internal hostname") {
			add(CapInternalHosts)
		}
		if strings.Contains(ev, "[x] service/version") {
			add(CapServiceVersion)
		}
		if strings.Contains(ev, "[x] credential") {
			add(CapCredCandidate)
		}
	case "exposure-path":
		add(CapAnonRead)
		add(CapInternalHosts)
	case "component-lead":
		add(CapServiceVersion)
	case "cors":
		add(CapAuthBoundary)
	}
	switch DetectorOf(f) {
	case "identity.oidc-surface@1":
		add(CapAuthBoundary)
	case "api.schema-exposure@1":
		add(CapAnonRead)
	case "storage.public-bucket@1":
		add(CapAnonRead)
	case "tech.service-fingerprint@1":
		add(CapServiceVersion)
	case "dns.dangling-cname@1":
		add(CapTakeover)
	case "http.open-redirect@1":
		add(CapRedirect)
	case "http.ssrf@1", "api.ssrf@1":
		add(CapServerSideFetch)
	}
	sort.Strings(caps)
	return caps
}

// ExtractPivots pulls internal hostnames, namespaces and versions from evidence
// (e.g. a Prometheus body) so an exposure becomes a pivot source, not a dead-end.
func ExtractPivots(body string) []string {
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

// PivotSummary renders extracted pivots for a finding.
func PivotSummary(f *Finding) string {
	if len(f.Pivots) == 0 {
		return ""
	}
	return fmt.Sprintf("Pivot intelligence extracted: %s", strings.Join(f.Pivots, "; "))
}
