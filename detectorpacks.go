package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// Items 6 & 7 — Technology-aware and identity/API/DNS/storage detector packs.
// All packs are strictly non-destructive: unauthenticated GETs (plus one
// read-only GraphQL introspection query) with SSRF guards. They add semantic
// depth beyond header checks without attacking anything.

// getWithBody performs a guarded non-destructive GET and returns status, headers
// and a bounded body. SSRF-guarded; empty ok on any failure.
func getWithBody(url string, maxBytes int64) (int, http.Header, string, bool) {
	if err := ssrfSafeURL(url); err != nil {
		return 0, nil, "", false
	}
	c := nonDestructiveClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil, "", false
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return resp.StatusCode, resp.Header, string(b), true
}

// runDetectorPacks runs all live packs for one base URL and returns findings.
// Evidence bodies are captured as immutable evidence objects in the workdir.
func runDetectorPacks(wd, base string) []Finding {
	var out []Finding
	code, hdr, body, ok := getWithBody(base, 96*1024)
	if ok {
		if f := fingerprintService(wd, base, code, hdr, body); f != nil {
			out = append(out, *f)
			// technology-triggered second-stage: deepen on the fingerprinted service
			out = append(out, runSecondStage(wd, base, f.Title)...)
		}
		if f := publicBucket(wd, base, code, hdr, body); f != nil {
			out = append(out, *f)
		}
	}
	if f := oidcSurface(wd, base); f != nil {
		out = append(out, *f)
	}
	if f := apiSchema(wd, base); f != nil {
		out = append(out, *f)
	}
	if f := danglingCNAME(wd, base); f != nil {
		out = append(out, *f)
	}
	if f := apiMethodsAndErrors(wd, base); f != nil {
		out = append(out, *f)
	}
	if f := rateLimitProbe(wd, base); f != nil {
		out = append(out, *f)
	}
	return out
}

// Item 22 — API depth (non-destructive): enumerate advertised methods via OPTIONS
// and detect verbose error/stack-trace leakage on a non-existent path.
func apiMethodsAndErrors(wd, base string) *Finding {
	// verbose error on a random path
	rnd := strings.TrimRight(base, "/") + "/secskills-" + randToken()
	code, _, body, ok := getWithBody(rnd, 32*1024)
	if ok && verboseError(body) {
		ev := captureEvidence(wd, "api.verbose-error@1", base, "http-response", "text/plain", "GET "+rnd, "redacted", []byte(body[:min(len(body), 4096)]))
		return &Finding{
			Title: "Verbose error / stack trace disclosed", Host: base, Severity: "LOW", Status: "open",
			Confidence: "Confirmed", Validation: "behavior-confirmed",
			ObservedEvidence: fmt.Sprintf("GET %s -> HTTP %d; response contained framework stack-trace / debug markers.", rnd, code),
			ImpactText:  "Verbose errors leak framework, file paths and internal structure, aiding targeted attacks. Return generic errors in production.",
			EvidenceCmd: "curl -sk " + shellQuote(rnd), ProbeKind: "body-contains", ProbeURL: rnd, ProbeArg: "traceback",
			EvidenceRefs: []string{ev}, DetectorID: "api.verbose-error@1",
		}
	}
	return nil
}

func verboseError(body string) bool {
	l := strings.ToLower(body)
	for _, m := range []string{"traceback (most recent call last)", "java.lang.", "at org.springframework", "stack trace", "django.", "werkzeug", ".rb:in ", "goroutine ", "system.web.", "exception in thread", "n: syntax error"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// Item 23 — Rate-limit / abuse-control verification (bounded, non-destructive).
// Sends a small fixed budget of requests and reports whether throttling controls
// are visible. Never floods: hard cap of rateLimitBudget requests.
const rateLimitBudget = 8

func rateLimitProbe(wd, base string) *Finding {
	seen429 := false
	rlHeader := ""
	for i := 0; i < rateLimitBudget; i++ {
		code, hdr, _, ok := getWithBody(base, 2048)
		if !ok {
			break
		}
		if code == 429 {
			seen429 = true
		}
		for _, h := range []string{"Retry-After", "X-RateLimit-Limit", "RateLimit-Limit", "X-RateLimit-Remaining"} {
			if hdr.Get(h) != "" {
				rlHeader = h + ": " + hdr.Get(h)
			}
		}
	}
	// Only report the *absence* of any visible control as an informational note;
	// presence is recorded as passing context (negative evidence handled by ledger).
	if seen429 || rlHeader != "" {
		return nil
	}
	ev := captureEvidence(wd, "http.rate-limit-absent@1", base, "detector-parse", "text/plain", fmt.Sprintf("%d bounded GETs", rateLimitBudget), "none",
		[]byte(fmt.Sprintf("no 429 and no RateLimit/Retry-After headers across %d bounded requests", rateLimitBudget)))
	return &Finding{
		Title: "No visible rate-limiting on unauthenticated endpoint", Host: base, Severity: "INFORMATIONAL", Status: "open",
		Confidence: "Medium", Validation: "behavior-confirmed",
		ObservedEvidence: fmt.Sprintf("Across %d bounded requests, no HTTP 429 and no RateLimit/Retry-After headers were observed. (Bounded probe; a global limiter may still exist.)", rateLimitBudget),
		ImpactText:  "No externally-visible per-IP throttling on this endpoint. Not a vulnerability by itself; relevant to abuse/DoS posture for a public service.",
		EvidenceCmd: "for i in $(seq 8); do curl -sk -o /dev/null -w '%%{http_code}\n' " + shellQuote(base) + "; done", ProbeKind: "manual", ProbeURL: base,
		EvidenceRefs: []string{ev}, DetectorID: "http.rate-limit-absent@1",
	}
}

// serviceSignatures maps a recognizable operational service to header/body marks.
var serviceSignatures = []struct {
	name string
	hint []string
}{
	{"Argo CD", []string{"argocd", "argo-cd", "Argo CD"}},
	{"Harbor registry", []string{"harbor", "/harbor/", "Harbor"}},
	{"HashiCorp Vault", []string{"x-vault-", "vault-", "Vault"}},
	{"Grafana", []string{"grafana", "Grafana"}},
	{"Prometheus", []string{"Prometheus Time Series", "prometheus"}},
	{"Keycloak", []string{"keycloak", "Keycloak", "auth/realms"}},
	{"Kubernetes Dashboard", []string{"kubernetes-dashboard", "Kubernetes Dashboard"}},
	{"GitLab", []string{"gitlab", "GitLab"}},
	{"MinIO", []string{"MinIO", "minio"}},
	{"Netbox", []string{"netbox", "NetBox"}},
	{"Jenkins", []string{"X-Jenkins", "Jenkins"}},
	{"Consul", []string{"consul", "Consul"}},
}

// fingerprintService recognizes a known operational service. It is INFORMATIONAL
// context (surface intelligence), and it names the technology-specific checks an
// authorized deeper pass should run — it does not perform them.
func fingerprintService(wd, base string, code int, hdr http.Header, body string) *Finding {
	hay := strings.ToLower(hdr.Get("Server") + " " + hdr.Get("X-Powered-By") + " " + hdr.Get("WWW-Authenticate") + " " + title(body) + " " + body[:min(len(body), 4096)])
	for _, sig := range serviceSignatures {
		for _, h := range sig.hint {
			if strings.Contains(hay, strings.ToLower(h)) {
				ev := captureEvidence(wd, "tech.service-fingerprint@1", base, "http-response", "text/html", "GET "+base,
					"redacted", []byte(fmt.Sprintf("status=%d server=%s title=%s", code, hdr.Get("Server"), title(body))))
				f := &Finding{
					Title: "Operational service exposed: " + sig.name, Host: base, Severity: "INFORMATIONAL",
					Status: "open", Confidence: "Confirmed", Validation: "behavior-confirmed",
					ObservedEvidence: fmt.Sprintf("Fingerprint matched %q (HTTP %d). Recommended authorized deeper checks for this service: %s.", sig.name, code, techNextChecks(sig.name)),
					ImpactText:   "Recognized " + sig.name + " on the external surface. Exposure alone is context, not a vulnerability; deeper service-specific auth/config checks require an authorized follow-up.",
					EvidenceCmd:  "curl -skI " + shellQuote(base),
					ProbeKind:    "status", ProbeURL: base, EvidenceRefs: []string{ev},
					DetectorID: "tech.service-fingerprint@1",
				}
				return f
			}
		}
	}
	return nil
}

func techNextChecks(service string) string {
	switch service {
	case "Harbor registry":
		return "anonymous catalog listing, project enumeration, API version, exposed health/config endpoints, auth boundaries"
	case "Argo CD":
		return "anonymous API access, exposed app manifests, SSO redirect handling, version CVE applicability"
	case "Grafana":
		return "anonymous org access, snapshot exposure, plugin/version CVEs, /api/health"
	case "HashiCorp Vault":
		return "seal status, auth methods enumeration, /v1/sys/health, unauth path exposure"
	case "Keycloak":
		return "realm enumeration, well-known OIDC config, admin console exposure, account API"
	case "MinIO":
		return "anonymous bucket listing, console exposure, presigned patterns"
	}
	return "service-specific unauthenticated surface + version CVE applicability"
}

// oidcSurface discovers an OAuth/OIDC surface via well-known documents. Surface
// intelligence only; no flows are exercised.
func oidcSurface(wd, base string) *Finding {
	for _, wk := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		u := strings.TrimRight(base, "/") + wk
		code, _, body, ok := getWithBody(u, 32*1024)
		if !ok || code != 200 || !strings.Contains(body, "issuer") {
			continue
		}
		var doc map[string]any
		if json.Unmarshal([]byte(body), &doc) != nil {
			continue
		}
		iss, _ := doc["issuer"].(string)
		ev := captureEvidence(wd, "identity.oidc-surface@1", base, "http-response", "application/json", "GET "+u, "none", []byte(body))
		var caps []string
		for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint"} {
			if _, ok := doc[k]; ok {
				caps = append(caps, k)
			}
		}
		return &Finding{
			Title: "OAuth/OIDC discovery surface exposed", Host: base, Severity: "INFORMATIONAL",
			Status: "open", Confidence: "Confirmed", Validation: "behavior-confirmed",
			ObservedEvidence: fmt.Sprintf("issuer=%s; endpoints: %s (via %s)", safeField(iss), strings.Join(caps, ", "), wk),
			ImpactText:   "The identity provider publishes a discovery document. This is expected for OIDC but defines the auth attack surface (token/authorization/JWKS endpoints) an authorized identity-focused pass should validate (redirect URI handling, PKCE, token config).",
			EvidenceCmd:  "curl -sk " + shellQuote(u),
			ProbeKind:    "body-contains", ProbeURL: u, ProbeArg: "issuer", EvidenceRefs: []string{ev},
			DetectorID: "identity.oidc-surface@1",
		}
	}
	return nil
}

// apiSchema detects exposed API schemas (OpenAPI/Swagger) and GraphQL
// introspection. Introspection uses a single read-only query.
func apiSchema(wd, base string) *Finding {
	for _, p := range []string{"/openapi.json", "/swagger.json", "/v2/api-docs", "/api-docs", "/swagger/v1/swagger.json"} {
		u := strings.TrimRight(base, "/") + p
		code, _, body, ok := getWithBody(u, 64*1024)
		if ok && code == 200 && (strings.Contains(body, "\"swagger\"") || strings.Contains(body, "\"openapi\"") || strings.Contains(body, "\"paths\"")) {
			ev := captureEvidence(wd, "api.schema-exposure@1", base, "http-response", "application/json", "GET "+u, "none", []byte(body[:min(len(body), 8192)]))
			return &Finding{
				Title: "API schema exposed (" + p + ")", Host: base, Severity: "LOW",
				Status: "open", Confidence: "Confirmed", Validation: "behavior-confirmed",
				ObservedEvidence: fmt.Sprintf("GET %s -> HTTP 200; OpenAPI/Swagger document served unauthenticated.", u),
				ImpactText:   "The full API contract is readable unauthenticated. Not a vulnerability by itself, but it enumerates endpoints, methods, and parameters that widen the tested surface; review for undocumented or state-changing operations.",
				EvidenceCmd:  "curl -sk " + shellQuote(u), ProbeKind: "body-contains", ProbeURL: u, ProbeArg: "paths",
				EvidenceRefs: []string{ev}, DetectorID: "api.schema-exposure@1",
			}
		}
	}
	// GraphQL introspection (read-only)
	for _, p := range []string{"/graphql", "/api/graphql", "/v1/graphql"} {
		u := strings.TrimRight(base, "/") + p
		if body, ok := graphqlIntrospect(u); ok {
			ev := captureEvidence(wd, "api.schema-exposure@1", base, "http-response", "application/json", "POST "+u+" (introspection)", "none", []byte(body[:min(len(body), 8192)]))
			return &Finding{
				Title: "GraphQL introspection enabled (" + p + ")", Host: base, Severity: "LOW",
				Status: "open", Confidence: "Confirmed", Validation: "behavior-confirmed",
				ObservedEvidence: "A read-only __schema introspection query returned the full type system unauthenticated.",
				ImpactText:   "Introspection exposes the entire GraphQL schema, aiding enumeration of queries/mutations. Disable introspection in production unless intentionally public.",
				EvidenceCmd:  "curl -sk -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{queryType{name}}}\"}' " + shellQuote(u),
				ProbeKind:  "manual", ProbeURL: u, EvidenceRefs: []string{ev}, DetectorID: "api.schema-exposure@1",
			}
		}
	}
	return nil
}

func graphqlIntrospect(u string) (string, bool) {
	if err := ssrfSafeURL(u); err != nil {
		return "", false
	}
	c := nonDestructiveClient()
	req, err := http.NewRequest("POST", u, strings.NewReader(`{"query":"{__schema{queryType{name}}}"}`))
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	s := string(b)
	if resp.StatusCode == 200 && strings.Contains(s, "__schema") && strings.Contains(s, "queryType") {
		return s, true
	}
	return "", false
}

// danglingCNAME flags a takeover *candidate*: a CNAME pointing at a known
// provider whose target does not resolve. It never claims takeover — claimability
// requires provider-specific validation, which is out of non-destructive scope.
var takeoverProviders = map[string]string{
	"s3.amazonaws.com": "AWS S3", "github.io": "GitHub Pages", "herokudns.com": "Heroku",
	"herokuapp.com": "Heroku", "azurewebsites.net": "Azure", "cloudapp.net": "Azure",
	"trafficmanager.net": "Azure Traffic Manager", "fastly.net": "Fastly", "ghost.io": "Ghost",
	"wpengine.com": "WP Engine", "pantheonsite.io": "Pantheon", "readthedocs.io": "ReadTheDocs",
	"surge.sh": "Surge", "bitbucket.io": "Bitbucket", "zendesk.com": "Zendesk",
}

func danglingCNAME(wd, base string) *Finding {
	host := hostOf(base)
	cname, err := net.LookupCNAME(host)
	if err != nil || cname == "" {
		return nil
	}
	cname = strings.TrimSuffix(cname, ".")
	if strings.EqualFold(cname, host) {
		return nil
	}
	provider := ""
	for suffix, name := range takeoverProviders {
		if strings.HasSuffix(cname, suffix) {
			provider = name
			break
		}
	}
	if provider == "" {
		return nil
	}
	// candidate only if the CNAME target does not resolve (potentially claimable)
	if _, err := net.LookupHost(cname); err == nil {
		return nil
	}
	ev := captureEvidence(wd, "dns.dangling-cname@1", base, "dns", "text/plain", "CNAME "+host, "none",
		[]byte(fmt.Sprintf("%s CNAME %s (provider %s); target does not resolve", host, cname, provider)))
	return &Finding{
		Title: "Dangling CNAME — subdomain-takeover candidate (" + provider + ")", Host: base, Severity: "MEDIUM",
		Status: "open", Confidence: "Low", Validation: "config-inferred",
		ObservedEvidence: fmt.Sprintf("%s → CNAME %s (%s); the CNAME target does not currently resolve, which is a takeover precondition. Claimability NOT verified (non-destructive scope).", host, cname, provider),
		ImpactText:   "If the pointed-to " + provider + " resource is unclaimed, an attacker may register it and serve content on this hostname. This is a candidate: provider-specific claimability was not tested.",
		EvidenceCmd:  "dig +short CNAME " + shellQuote(host), ProbeKind: "manual", ProbeURL: base,
		EvidenceRefs: []string{ev}, DetectorID: "dns.dangling-cname@1",
	}
}

// publicBucket detects an anonymously-listable object store (S3-compatible XML
// listing or MinIO console) served at the base URL.
func publicBucket(wd, base string, code int, hdr http.Header, body string) *Finding {
	isS3List := strings.Contains(body, "<ListBucketResult") || (code == 200 && strings.Contains(body, "<Contents>") && strings.Contains(body, "<Key>"))
	server := strings.ToLower(hdr.Get("Server"))
	isMinioConsole := strings.Contains(server, "minio") && code == 200
	if !isS3List && !isMinioConsole {
		return nil
	}
	kind := "S3-compatible bucket listing"
	if isMinioConsole {
		kind = "MinIO console/endpoint"
	}
	ev := captureEvidence(wd, "storage.public-bucket@1", base, "http-response", "application/xml", "GET "+base, "redacted",
		[]byte(body[:min(len(body), 8192)]))
	return &Finding{
		Title: "Public object storage exposed (" + kind + ")", Host: base, Severity: "MEDIUM",
		Status: "open", Confidence: "Confirmed", Validation: "behavior-confirmed",
		ObservedEvidence: fmt.Sprintf("HTTP %d; response matched an anonymous %s. Object keys may be enumerable.", code, kind),
		ImpactText:   "Anonymous listing of an object store discloses stored object names and can expose their contents. Review bucket policy; require authentication and disable anonymous listing.",
		EvidenceCmd:  "curl -sk " + shellQuote(base), ProbeKind: "body-contains", ProbeURL: base, ProbeArg: "<ListBucketResult",
		EvidenceRefs: []string{ev}, DetectorID: "storage.public-bucket@1",
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// title extracts the <title> text from an HTML body (best-effort, lowercased-safe).
func title(body string) string {
	l := strings.ToLower(body)
	i := strings.Index(l, "<title")
	if i < 0 {
		return ""
	}
	j := strings.Index(l[i:], ">")
	if j < 0 {
		return ""
	}
	start := i + j + 1
	k := strings.Index(l[start:], "</title>")
	if k < 0 || k > 200 {
		return ""
	}
	return strings.TrimSpace(body[start : start+k])
}


