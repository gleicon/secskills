package main

import (
	"fmt"
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------
// Item 4 — Formal evidence state machine.
// A finding's epistemic state is explicit and only moves along defined edges.
// This prevents illegitimate jumps (e.g. a version banner silently becoming
// CONFIRMED because a severity classifier changed).
// ---------------------------------------------------------------------------

type EvidenceState string

const (
	StDiscovered      EvidenceState = "DISCOVERED"
	StObserved        EvidenceState = "OBSERVED"
	StInferred        EvidenceState = "INFERRED"
	StConfirmed       EvidenceState = "CONFIRMED"
	StExploitValidated EvidenceState = "EXPLOIT_VALIDATED"
	StSuppressed      EvidenceState = "SUPPRESSED"
	StNotApplicable   EvidenceState = "NOT_APPLICABLE"
	StInconclusive    EvidenceState = "INCONCLUSIVE"
	StError           EvidenceState = "ERROR"
)

// evidenceTransitions defines the only legal state moves. A transition not in
// this table is rejected by canTransition — the state machine is closed.
var evidenceTransitions = map[EvidenceState][]EvidenceState{
	StDiscovered:      {StObserved, StInferred, StNotApplicable, StInconclusive, StError, StSuppressed},
	StObserved:        {StConfirmed, StInferred, StInconclusive, StNotApplicable, StError, StSuppressed},
	StInferred:        {StConfirmed, StExploitValidated, StSuppressed, StInconclusive, StNotApplicable, StError},
	StConfirmed:       {StExploitValidated, StSuppressed, StInconclusive, StError},
	StExploitValidated: {StSuppressed},
	StInconclusive:    {StObserved, StConfirmed, StInferred, StNotApplicable, StError, StSuppressed},
	// terminal-ish states
	StSuppressed:    {},
	StNotApplicable: {},
	StError:         {StInconclusive, StObserved},
}

func canTransition(from, to EvidenceState) bool {
	for _, s := range evidenceTransitions[from] {
		if s == to {
			return true
		}
	}
	return from == to
}

// stateForValidation maps the finding's validation tag to a formal state, so the
// existing detector output feeds the state machine without a second source of truth.
func stateForValidation(validation string) EvidenceState {
	switch validation {
	case "exploited":
		return StExploitValidated
	case "behavior-confirmed":
		return StConfirmed
	case "passive":
		return StObserved
	case "config-inferred", "version-inferred":
		return StInferred
	case "inconclusive":
		return StInconclusive
	case "not-applicable":
		return StNotApplicable
	}
	return StObserved
}

// ---------------------------------------------------------------------------
// Item 13 — Severity rubric independent of CVSS.
// HIGH/MEDIUM/LOW are defined by demonstrated conditions, not by the CVSS band,
// so detector authors cannot drift severity. assessSeverity returns the rubric
// severity plus the clause that justifies it; severityDrift flags a mismatch
// against what the detector set.
// ---------------------------------------------------------------------------

// severityRubric is the human-readable policy, rendered into the report so the
// severity of every finding is auditable against a fixed standard.
func severityRubric() string {
	return strings.Join([]string{
		"**HIGH** — at least one of: confirmed sensitive-data disclosure; confirmed unauthorized state-changing action; a validated, remotely-reachable exploit primitive; or a material authentication/authorization weakness.",
		"**MEDIUM** — a confirmed weakness that is exploitable only with a precondition (network position, a second flaw, specific client), or unauthenticated exposure of non-sensitive operational data.",
		"**LOW** — a defense-in-depth / hardening deviation with no demonstrated exploit prerequisite.",
		"**INFORMATIONAL** — an observation with no security weakness; context only.",
		"CVSS base score is computed separately (FIRST.org). Where the rubric severity differs from the CVSS band, the finding states the reason; the rubric governs the assessment severity.",
	}, "\n\n")
}

// assessSeverity applies the rubric to a finding using its type, confidence and
// observed evidence. Returns the rubric severity and the justifying clause.
func assessSeverity(f *Finding) (string, string) {
	ft := findingType(f)
	confirmed := f.Validation == "behavior-confirmed" || f.Validation == "exploited"
	ev := strings.ToLower(f.ObservedEvidence)
	switch ft {
	case "metrics-exposed":
		if strings.Contains(ev, "[x] credential") || strings.Contains(ev, "[x] bearer") {
			return "HIGH", "confirmed sensitive-data disclosure (credential/token class observed)"
		}
		if strings.Contains(ev, "[x] internal hostname") || strings.Contains(ev, "[x] namespace") || strings.Contains(ev, "[x] private/internal ip") {
			return "MEDIUM", "confirmed unauthenticated exposure of internal-topology data (no credentials observed)"
		}
		return "LOW", "unauthenticated operational endpoint returning only generic runtime data"
	case "exposure-path":
		// a reachable sensitive path (VCS/config/debug artifact) is MEDIUM by
		// default; HIGH only when secret/credential content is actually observed.
		if strings.Contains(ev, "[x] credential") || strings.Contains(ev, "secret") || strings.Contains(ev, "private key") {
			return "HIGH", "unauthenticated exposure with secret/credential content observed"
		}
		return "MEDIUM", "unauthenticated exposure of a sensitive path (VCS/config/debug artifact)"
	case "tls-deprecated":
		return "MEDIUM", "confirmed weak transport config; exploitation requires on-path network position"
	case "cors":
		// only credentialed permissive CORS is a weakness; "without credentials"
		// in the title must not trip the credential match.
		t := strings.ToLower(f.Title)
		credentialed := (strings.Contains(t, "credential") && !strings.Contains(t, "without credential")) || strings.Contains(t, "acac")
		if credentialed {
			return "MEDIUM", "permissive CORS combined with credentials; depends on sensitive readable data"
		}
		return "INFORMATIONAL", "permissive origin without credentials — no authenticated data exposed"
	case "hsts-missing", "csp-missing", "nosniff-missing", "xfo-missing":
		return "LOW", "hardening deviation with no demonstrated exploit prerequisite"
	case "component-lead":
		return "LOW", "version-inferred lead; exploitability not established"
	}
	if !confirmed {
		return "LOW", "unconfirmed / defense-in-depth"
	}
	return f.Severity, "detector-assigned severity retained (no rubric override applies)"
}

// severityDrift returns a non-empty note when the detector-set severity does not
// match the rubric — surfaced in QA and the conformance suite.
func severityDrift(f *Finding) string {
	want, reason := assessSeverity(f)
	if !strings.EqualFold(want, f.Severity) {
		return fmt.Sprintf("severity drift: detector=%s rubric=%s (%s)", f.Severity, want, reason)
	}
	return ""
}

// ---------------------------------------------------------------------------
// Item 9 — Detector-version migration metadata.
// Each detector id carries an @version. The registry records how a version
// supersedes the prior one and whether identity/severity semantics changed, so
// an engine upgrade does not spuriously mark findings fixed/new.
// ---------------------------------------------------------------------------

type DetectorMeta struct {
	ID                  string `json:"id"`
	Supersedes          string `json:"supersedes,omitempty"`
	IdentityCompatible  bool   `json:"identity_compatible"`
	SeverityModelChanged bool  `json:"severity_model_changed"`
	Description         string `json:"description"`
}

// detectorRegistry is the authoritative detector-pack manifest. rulesetSHA()
// hashes the ids; this adds the migration semantics around them.
func detectorRegistry() []DetectorMeta {
	return []DetectorMeta{
		{ID: "tls.deprecated-protocol@1", IdentityCompatible: true, Description: "deprecated TLS protocol accepted"},
		{ID: "http.header.hsts-missing@1", IdentityCompatible: true, Description: "HSTS header absent"},
		{ID: "http.header.csp-missing@1", IdentityCompatible: true, Description: "CSP header absent"},
		{ID: "http.header.nosniff-missing@1", IdentityCompatible: true, Description: "X-Content-Type-Options absent"},
		{ID: "http.header.xfo-missing@1", IdentityCompatible: true, Description: "X-Frame-Options / frame-ancestors absent"},
		{ID: "http.cors@1", IdentityCompatible: true, Description: "cross-origin policy weakness"},
		{ID: "http.prometheus.public-metrics@1", IdentityCompatible: true, Description: "unauthenticated Prometheus metrics"},
		{ID: "http.exposure-path@1", IdentityCompatible: true, Description: "unauthenticated sensitive path"},
		{ID: "component.banner-osv-correlation@1", IdentityCompatible: true, Description: "banner-inferred component CVE lead"},
		{ID: "content.prompt-injection@1", IdentityCompatible: true, Description: "prompt-injection content in target data"},
		{ID: "tech.service-fingerprint@1", IdentityCompatible: true, Description: "known operational service fingerprint"},
		{ID: "identity.oidc-surface@1", IdentityCompatible: true, Description: "OAuth/OIDC discovery surface"},
		{ID: "api.schema-exposure@1", IdentityCompatible: true, Description: "OpenAPI/GraphQL schema exposure"},
		{ID: "dns.dangling-cname@1", IdentityCompatible: true, Description: "dangling CNAME takeover candidate"},
		{ID: "storage.public-bucket@1", IdentityCompatible: true, Description: "public object-storage listing"},
		{ID: "nuclei@1", IdentityCompatible: true, Description: "nuclei template match"},
		{ID: "generic@1", IdentityCompatible: true, Description: "unclassified finding"},
	}
}

// detectorMigrationImpact compares two detector manifests and reports the effect
// on finding identity — the engine-change impact analysis an auditor expects.
func detectorMigrationImpact(prev, cur []DetectorMeta) string {
	pm := map[string]DetectorMeta{}
	for _, d := range prev {
		pm[d.ID] = d
	}
	var lines []string
	for _, d := range cur {
		if _, ok := pm[d.ID]; !ok {
			note := "new detector — findings will appear as NEW (expected)"
			if d.Supersedes != "" {
				comp := "identity preserved"
				if !d.IdentityCompatible {
					comp = "identity CHANGED — prior findings may re-key"
				}
				note = fmt.Sprintf("supersedes %s; %s", d.Supersedes, comp)
			}
			lines = append(lines, fmt.Sprintf("+ %s — %s", d.ID, note))
		}
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		return "No detector-identity changes between the compared manifests."
	}
	return strings.Join(lines, "\n")
}
