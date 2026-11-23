package finding

import (
	"strings"
)

// ---------------------------------------------------------------------------
// Item 4 — Explicit evidence states.
// A finding's epistemic state is derived from how it was validated, never from
// its severity, so a version banner cannot become CONFIRMED because a severity
// classifier changed.
// ---------------------------------------------------------------------------

// EvidenceState is how far a finding has been validated.
type EvidenceState string

// Evidence states.
const (
	StObserved         EvidenceState = "OBSERVED"
	StInferred         EvidenceState = "INFERRED"
	StConfirmed        EvidenceState = "CONFIRMED"
	StExploitValidated EvidenceState = "EXPLOIT_VALIDATED"
	StNotApplicable    EvidenceState = "NOT_APPLICABLE"
	StInconclusive     EvidenceState = "INCONCLUSIVE"
)

// stateForValidation maps the finding's validation tag to its evidence state,
// so detector output is the single source of truth.
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

// SeverityRubric is the human-readable policy, rendered into the report so the
// severity of every finding is auditable against a fixed standard.
func SeverityRubric() string {
	return strings.Join([]string{
		"**HIGH** — at least one of: confirmed sensitive-data disclosure; confirmed unauthorized state-changing action; a validated, remotely-reachable exploit primitive; or a material authentication/authorization weakness.",
		"**MEDIUM** — a confirmed weakness that is exploitable only with a precondition (network position, a second flaw, specific client), or unauthenticated exposure of non-sensitive operational data.",
		"**LOW** — a defense-in-depth / hardening deviation with no demonstrated exploit prerequisite.",
		"**INFORMATIONAL** — an observation with no security weakness; context only.",
		"CVSS base score is computed separately (FIRST.org). Where the rubric severity differs from the CVSS band, the finding states the reason; the rubric governs the assessment severity.",
		"**Severity is impact-if-true and does NOT imply validation.** A finding's `State` (CONFIRMED / OBSERVED / INFERRED / INCONCLUSIVE) carries the validation status. A MEDIUM/INCONCLUSIVE finding means \"medium impact IF the condition holds; not confirmed this run\" — it is not a confirmed medium weakness.",
	}, "\n\n")
}

// AssessSeverity applies the rubric to a finding using its type, confidence and
// observed evidence. Returns the rubric severity and the justifying clause.
func AssessSeverity(f *Finding) (string, string) {
	ft := FindingType(f)
	confirmed := f.Validation == "behavior-confirmed" || f.Validation == "exploited"
	ev := strings.ToLower(f.ObservedEvidence)
	switch ft {
	case "metrics-exposed":
		// HIGH requires a VALIDATED secret value, not a mere pattern match. A
		// credential-like *pattern* is an unvalidated hypothesis -> MEDIUM (with a
		// potential-HIGH escalation recorded by enforceSeverityPolicy).
		if strings.Contains(ev, "[x] credential value confirmed") || strings.Contains(ev, "[x] bearer token / api key value") {
			return "HIGH", "validated credential/token value disclosed unauthenticated"
		}
		if strings.Contains(ev, "[x] credential-like pattern") {
			return "MEDIUM", "unvalidated credential-like pattern in unauthenticated metrics (potential HIGH if confirmed a real secret)"
		}
		if strings.Contains(ev, "[x] internal hostname") || strings.Contains(ev, "[x] namespace") || strings.Contains(ev, "[x] private/internal ip") {
			return "MEDIUM", "confirmed unauthenticated exposure of internal-topology data (no credentials observed)"
		}
		return "LOW", "unauthenticated operational endpoint returning only generic runtime data"
	case "exposure-path":
		// A reachable .env serves application credentials, and a reachable .git
		// serves full source and commit history (routinely with secrets) — both
		// are HIGH by what the path is, not only when a secret string is sniffed.
		// Other sensitive paths (dir listing, server-status) stay MEDIUM unless
		// secret/credential content is actually observed.
		loc := strings.ToLower(f.Host + " " + f.Title)
		switch {
		case strings.Contains(ev, "[x] credential") || strings.Contains(ev, "secret") || strings.Contains(ev, "private key"):
			return "HIGH", "unauthenticated exposure with secret/credential content observed"
		case strings.Contains(loc, ".env") || strings.Contains(loc, "dotenv") || strings.Contains(loc, "environment file"):
			return "HIGH", "unauthenticated exposure of an environment file (application credentials retrievable)"
		case strings.Contains(loc, ".git") || strings.Contains(loc, "version-control") || strings.Contains(loc, "version control"):
			return "HIGH", "unauthenticated exposure of version-control metadata (source and history retrievable)"
		}
		return "MEDIUM", "unauthenticated exposure of a sensitive path (config/debug artifact)"
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
	case "llm-canary":
		return "MEDIUM", "planted canary echoed by LLM endpoint; intermediary retains/reflects prompt content (AC-2 indicator)"
	case "llm-drift":
		return "LOW", "deterministic-oracle drift across warm-up rounds; temperature/instruction confound noted"
	case "llm-sysleak":
		return "MEDIUM", "chatbot disclosed system instructions on direct request; enables guardrail-bypass design"
	case "component-lead":
		if strings.Contains(ev, "[x] cisa kev") {
			return "MEDIUM", "version-inferred lead for a CVE exploited in the wild (CISA KEV); validate the running build first"
		}
		return "LOW", "version-inferred lead; exploitability not established"
	case "datastore-open":
		return "HIGH", "confirmed unauthenticated or default-credential access to an internet-reachable datastore"
	}
	if !confirmed {
		return "LOW", "unconfirmed / defense-in-depth"
	}
	return f.Severity, "detector-assigned severity retained (no rubric override applies)"
}

// ---------------------------------------------------------------------------
// Item 9 — Detector-version migration metadata.
// Each detector id carries an @version. The registry records how a version
// supersedes the prior one and whether identity/severity semantics changed, so
// an engine upgrade does not spuriously mark findings fixed/new.
// ---------------------------------------------------------------------------

// DetectorMeta describes a detector version and its compatibility with the one
// it supersedes.
type DetectorMeta struct {
	ID                   string `json:"id"`
	Supersedes           string `json:"supersedes,omitempty"`
	IdentityCompatible   bool   `json:"identity_compatible"`
	SeverityModelChanged bool   `json:"severity_model_changed"`
	Description          string `json:"description"`
}

// DetectorRegistry is the authoritative detector-pack manifest. rulesetSHA()
// hashes the ids; this adds the migration semantics around them.
func DetectorRegistry() []DetectorMeta {
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
		{ID: "component.banner-nvd-range@1", IdentityCompatible: true, Description: "banner version inside an NVD CVE range (network sweep lead)"},
		{ID: "datastore.unauthenticated@1", IdentityCompatible: true, Description: "datastore open without auth or with a vendor default credential"},
		{ID: "content.prompt-injection@1", IdentityCompatible: true, Description: "prompt-injection content in target data"},
		{ID: "llm.canary-reflection@1", IdentityCompatible: true, Description: "LLM endpoint reflects planted canary (AC-2 logging indicator)"},
		{ID: "llm.response-drift@1", IdentityCompatible: true, Description: "deterministic-oracle drift across warm-up rounds (AC-1.b indicator)"},
		{ID: "llm.system-prompt-leak@1", IdentityCompatible: true, Description: "chatbot discloses system prompt on direct request"},
		{ID: "tech.service-fingerprint@1", IdentityCompatible: true, Description: "known operational service fingerprint"},
		{ID: "identity.oidc-surface@1", IdentityCompatible: true, Description: "OAuth/OIDC discovery surface"},
		{ID: "api.schema-exposure@1", IdentityCompatible: true, Description: "OpenAPI/GraphQL schema exposure"},
		{ID: "dns.dangling-cname@1", IdentityCompatible: true, Description: "dangling CNAME takeover candidate"},
		{ID: "storage.public-bucket@1", IdentityCompatible: true, Description: "public object-storage listing"},
		{ID: "api.verbose-error@1", IdentityCompatible: true, Description: "verbose error / stack trace disclosure"},
		{ID: "http.rate-limit-absent@1", IdentityCompatible: true, Description: "no visible unauthenticated rate-limiting"},
		{ID: "dns.spf-missing@1", IdentityCompatible: true, Description: "no SPF record"},
		{ID: "dns.spf-weak@1", IdentityCompatible: true, Description: "permissive SPF (+all)"},
		{ID: "dns.dmarc-missing@1", IdentityCompatible: true, Description: "no DMARC record"},
		{ID: "dns.dmarc-none@1", IdentityCompatible: true, Description: "DMARC p=none"},
		{ID: "dns.wildcard@1", IdentityCompatible: true, Description: "wildcard DNS"},
		{ID: "dns.dnssec-unknown@1", IdentityCompatible: true, Description: "DNSSEC not evaluated"},
		{ID: "http.authz-bypass@1", IdentityCompatible: true, Description: "authorization bypass via request variant"},
		{ID: "http.authz-boundary@1", IdentityCompatible: true, Description: "authorization boundary resisted bypass classes (negative evidence)"},
		{ID: "http.open-redirect@1", IdentityCompatible: true, Description: "open redirect to attacker-controlled host"},
		{ID: "ssti.arithmetic@1", IdentityCompatible: true, Description: "server-side template injection (arithmetic evaluated)"},
		{ID: "http.ssrf@1", IdentityCompatible: true, Description: "server-side request forgery (OAST-validated)"},
		{ID: "edge.origin-exposure@1", IdentityCompatible: true, Description: "origin reachable directly, bypassing the CDN/WAF"},
		{ID: "edge.header-acl-bypass@1", IdentityCompatible: true, Description: "access-control bypass via trusted header"},
		{ID: "tech.second-stage@1", IdentityCompatible: true, Description: "technology-triggered second-stage anonymous check"},
		{ID: "pivot.internal-host-reachable@1", IdentityCompatible: true, Description: "disclosed internal hostname resolves publicly (runtime pivot)"},
		{ID: "auth.jwt@1", IdentityCompatible: true, Description: "JWT weakness (alg:none / weak alg / no-exp / sensitive claim)"},
		{ID: "auth.cookie-flags@1", IdentityCompatible: true, Description: "session cookie missing Secure/HttpOnly/SameSite"},
		{ID: "authz.bola-candidate@1", IdentityCompatible: true, Description: "potential BOLA/IDOR (object readable by two identities)"},
		{ID: "nuclei@1", IdentityCompatible: true, Description: "nuclei template match"},
		{ID: "generic@1", IdentityCompatible: true, Description: "unclassified finding"},
	}
}

// HasValidatedPrimitive reports whether a finding carries a demonstrated,
// validated impact primitive that can justify HIGH under the rubric.
func HasValidatedPrimitive(f *Finding) bool {
	if f.Validation == "exploited" {
		return true
	}
	ev := strings.ToLower(f.ObservedEvidence)
	switch FindingType(f) {
	case "datastore-open":
		return strings.Contains(ev, "[x] unauthenticated datastore access") ||
			strings.Contains(ev, "[x] vendor default credential accepted")
	case "metrics-exposed", "exposure-path":
		// A confirmed retrieval of a .env (application credentials) or a .git
		// tree (source + history) is itself the validated disclosure primitive,
		// not merely a potential one — so these stay HIGH rather than being
		// demoted to potential-HIGH/MEDIUM.
		return strings.Contains(ev, "credential value confirmed") ||
			strings.Contains(ev, "[x] bearer token / api key value") ||
			strings.Contains(ev, "[x] private key") ||
			strings.Contains(ev, "[x] credential-like keys exposed") ||
			strings.Contains(ev, "[x] version-control metadata exposed")
	}
	return false
}

// EnforceSeverityPolicy makes the rubric authoritative and enforces the HIGH
// invariant: a HIGH must carry a validated primitive, else it is capped and the
// escalation condition is recorded. Automation never silently keeps an
// unsupported HIGH. Called at write time and idempotent.
func EnforceSeverityPolicy(f *Finding) {
	// An inconclusive finding keeps the severity the detector assigned as
	// "impact-if-true"; we do not upgrade it (an unvalidated observation must not
	// be promoted to a confirmed weakness). State carries the epistemic status.
	if IsInconclusive(f) {
		return
	}
	want, _ := AssessSeverity(f)
	// let the rubric drive known families
	if want != "" && !strings.EqualFold(want, f.Severity) {
		if FindingType(f) != "" {
			f.Severity = want
		}
	}
	if strings.EqualFold(f.Severity, "HIGH") && !HasValidatedPrimitive(f) {
		f.PotentialSeverity = "HIGH"
		f.Severity = "MEDIUM"
		if f.EscalationCondition == "" {
			f.EscalationCondition = "escalates to HIGH if the unvalidated primitive is manually confirmed (e.g. credential-like match verified as a real secret)"
		}
	}
}
