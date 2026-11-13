package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/textutil"
)

// M12 — Credentialed depth (authorized-exploit profile).
// With operator-supplied credentials the engine can test what unauthenticated
// scanning cannot: JWT weaknesses, session-cookie hardening, and — with a SECOND
// identity — authorization/BOLA differentials. All GET-only and non-destructive;
// no credential brute force, no state change.

// JWTInspect decodes a JWT (no signature verification) and flags weak algorithms,
// missing/expired exp, and sensitive claims. Detects the classic alg:none flaw.
func JWTInspect(token string) []finding.Finding {
	token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	dec := func(s string) map[string]any {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		var m map[string]any
		json.Unmarshal(b, &m)
		return m
	}
	hdr := dec(parts[0])
	pl := dec(parts[1])
	if hdr == nil || pl == nil {
		return nil
	}
	var out []finding.Finding
	mk := func(title, sev, ev, impact string) {
		out = append(out, finding.Finding{
			Title: title, Host: "supplied JWT", Severity: sev, Status: "open",
			Confidence: "Confirmed", Validation: "behavior-confirmed",
			ObservedEvidence: ev, ImpactText: impact,
			ProbeKind: "manual", ProbeURL: "jwt", DetectorID: "auth.jwt@1",
		})
	}
	alg, _ := hdr["alg"].(string)
	switch strings.ToLower(alg) {
	case "none":
		mk("JWT uses alg:none (signature not verified)", "HIGH", "JWT header alg=none — tokens are unsigned; an attacker can forge arbitrary claims.",
			"With alg:none the server accepts unsigned tokens, allowing full identity/claim forgery. Reject alg:none and pin expected algorithms.")
	case "hs256", "hs384", "hs512":
		mk("JWT uses a symmetric algorithm ("+alg+")", "LOW", "JWT alg="+alg+" (HMAC). If the secret is weak or shared, tokens can be forged.",
			"Symmetric-signed JWTs are forgeable if the secret leaks or is guessable. Prefer asymmetric (RS/ES) and rotate secrets.")
	}
	// exp checks
	if exp, ok := pl["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			mk("Supplied JWT is expired but was accepted", "MEDIUM", fmt.Sprintf("JWT exp=%d is in the past; if the server still accepts it, expiry is not enforced.", int64(exp)),
				"Tokens past their exp must be rejected. Verify server-side expiry enforcement.")
		}
	} else {
		mk("JWT has no expiry (exp) claim", "MEDIUM", "The supplied JWT has no exp claim — tokens never expire.",
			"Tokens without expiry remain valid indefinitely if leaked. Add and enforce a short exp.")
	}
	// sensitive claims
	for k := range pl {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "password") || strings.Contains(lk, "secret") || strings.Contains(lk, "ssn") || strings.Contains(lk, "credit") {
			mk("JWT payload carries a sensitive claim ("+k+")", "MEDIUM", "JWT payload includes a sensitive-looking claim: "+textutil.SafeField(k)+". JWT payloads are base64, not encrypted.",
				"JWT payloads are readable by anyone holding the token. Never place secrets/PII in claims.")
			break
		}
	}
	return out
}

// AuthzDifferential compares the same URL fetched as identity A and identity B.
// If both identities receive an identical 200 body for an object-style URL, the
// object may not be scoped to a user (potential BOLA/IDOR). Reported as a
// manual-confirm candidate — object user-ownership cannot be proven externally.
func AuthzDifferential(wd, url string, credA, credB map[string]string) *finding.Finding {
	body := func(cred map[string]string) (int, string) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return 0, ""
		}
		req.Header.Set("User-Agent", fetch.UserAgent)
		for k, v := range cred {
			req.Header.Set(k, v)
		}
		resp, err := fetch.CredentialedClient().Do(req)
		if err != nil {
			return 0, ""
		}
		b := make([]byte, 16384)
		n, _ := fetch.ReadFull(resp.Body, b)
		resp.Body.Close()
		return resp.StatusCode, string(b[:n])
	}
	ca, ba := body(credA)
	cb, bb := body(credB)
	// only interesting for object-style URLs (contain an id-looking segment) that
	// both identities can read identically.
	if ca == 200 && cb == 200 && ba != "" && ba == bb && looksLikeObjectURL(url) {
		ev := finding.CaptureEvidence(wd, "authz.bola-candidate@1", url, "http-response", "text/plain", "GET "+url+" as identity A and B", "redacted",
			[]byte("identical 200 body returned to two distinct identities"))
		return &finding.Finding{
			Title: "Potential BOLA/IDOR — object readable by two identities", Host: url, Severity: "MEDIUM", Status: "open",
			Confidence: "Low", Validation: "config-inferred",
			ObservedEvidence: "An object-style URL returned a byte-identical 200 response to two different authenticated identities. If the object is meant to be user-scoped, this is broken object-level authorization. Object ownership cannot be proven externally — manual confirmation required.",
			ImpactText:       "Broken object-level authorization (BOLA/IDOR) lets a user read another user's objects. Confirm the object should be user-scoped, then enforce per-object authorization.",
			EvidenceCmd:      "compare: curl -sk -H 'Authorization: <A>' " + netsec.ShellQuote(url) + " vs <B>",
			ProbeKind:        "manual", ProbeURL: url, EvidenceRefs: []string{ev}, DetectorID: "authz.bola-candidate@1",
			Capabilities: []string{finding.CapAuthBoundary},
		}
	}
	return nil
}

func looksLikeObjectURL(u string) bool {
	// a path segment that is all digits or a UUID-ish token suggests an object id
	path := u
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.IndexByte(u[i+3:], '/'); j >= 0 {
			path = u[i+3+j:]
		} else {
			return false
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if len(seg) >= 2 && (allDigits(seg) || looksUUID(seg)) {
			return true
		}
	}
	return false
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func looksUUID(s string) bool {
	return len(s) >= 32 && strings.Count(s, "-") >= 2
}
