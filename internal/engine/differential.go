package engine

import (
	"net/http"
	"strings"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/textutil"
)

// Item 10 — Environmental ambiguity → INCONCLUSIVE (never a silent PASS).
// A CDN challenge, bot-block, rate-limit, or auth gateway means "we could not
// observe the control", not "the control is present". These are classified so
// affected probes are marked inconclusive rather than passed.
func responseAmbiguity(code int, hdr http.Header, body string) (bool, string) {
	server := strings.ToLower(hdr.Get("Server"))
	l := strings.ToLower(body)
	switch {
	case code == 429:
		return true, "rate-limited (HTTP 429) at test time"
	case code == 503 && (strings.Contains(l, "cloudflare") || strings.Contains(server, "cloudflare")):
		return true, "Cloudflare 503 challenge/overload at test time"
	case code == 401 || code == 407:
		return true, "authentication gateway (HTTP " + textutil.Itoa(code) + ") — control state not observable unauthenticated"
	case strings.Contains(l, "cf-challenge") || strings.Contains(l, "just a moment") || hdr.Get("cf-mitigated") != "":
		return true, "Cloudflare bot challenge interstitial"
	case strings.Contains(l, "captcha") || strings.Contains(l, "are you a robot"):
		return true, "CAPTCHA/anti-bot interstitial"
	case hdr.Get("X-Datadome") != "" || strings.Contains(l, "datadome"):
		return true, "DataDome bot mitigation"
	case code == 0:
		return true, "no response (connection failed) at test time"
	}
	return false, ""
}

// corsOriginMatrix probes a small set of Origins (read-only, GET) and reports
// whether the endpoint reflects an arbitrary origin — the differential CORS test.
func corsOriginMatrix(url string) (reflectsArbitrary bool, allowsCreds bool, ok bool) {
	if err := netsec.SSRFSafeURL(url); err != nil {
		return false, false, false
	}
	probe := func(origin string) (string, string, bool) {
		c := fetch.NonDestructiveClient()
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", "", false
		}
		req.Header.Set("User-Agent", fetch.UserAgent)
		req.Header.Set("Origin", origin)
		resp, err := c.Do(req)
		if err != nil {
			return "", "", false
		}
		resp.Body.Close()
		return resp.Header.Get("Access-Control-Allow-Origin"), resp.Header.Get("Access-Control-Allow-Credentials"), true
	}
	evil := "https://secskills-evil-" + textutil.RandToken() + ".example"
	acao, acac, got := probe(evil)
	if !got {
		return false, false, false
	}
	return acao == evil, strings.EqualFold(acac, "true"), true
}

// CORSDifferential actively confirms arbitrary-origin reflection using the origin
// matrix, producing a behavior-confirmed CORS finding (distinct from the passive
// header check). Only reflection of an attacker origin is reported; the severity
// still depends on whether credentials are allowed.
func CORSDifferential(wd, url string) *finding.Finding {
	reflects, creds, ok := corsOriginMatrix(url)
	if !ok || !reflects {
		return nil
	}
	sev, title, impact := "LOW", "CORS reflects arbitrary Origin (no credentials)",
		"The endpoint echoes any request Origin into Access-Control-Allow-Origin. Without Allow-Credentials no authenticated data is exposed, but it removes the same-origin barrier for readable responses."
	if creds {
		sev, title, impact = "MEDIUM", "CORS reflects arbitrary Origin WITH credentials (ACAC:true)",
			"The endpoint reflects any Origin and allows credentials, so any site can read authenticated responses on behalf of a logged-in user. Confirm the endpoint returns sensitive data."
	}
	ev := finding.CaptureEvidence(wd, "http.cors@1", url, "http-response", "text/plain", "GET "+url+" (Origin matrix)", "none",
		[]byte("reflected attacker Origin in ACAO; ACAC="+boolStr(creds)))
	return &finding.Finding{
		Title: title, Host: url, Severity: sev, Status: "open",
		Confidence: "Confirmed", Validation: "behavior-confirmed",
		ObservedEvidence: "Differential Origin test: a random attacker Origin was reflected verbatim in Access-Control-Allow-Origin; Access-Control-Allow-Credentials=" + boolStr(creds) + ".",
		ImpactText:       impact,
		EvidenceCmd:      "curl -sk -H 'Origin: https://evil.example' -I " + netsec.ShellQuote(url) + " | grep -i access-control",
		ProbeKind:        "manual", ProbeURL: url, EvidenceRefs: []string{ev}, DetectorID: "http.cors@1",
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
