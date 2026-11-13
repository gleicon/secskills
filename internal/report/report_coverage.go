package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
)

// renderCoverageFunnel makes discovery coverage distinct from security coverage
// (audit item: "40 services tested" must not be read as "everything tested").
// Numbers come from the pipeline artifacts in the workdir.
func renderCoverageFunnel(wd string, live []tooling.LiveHost) string {
	subs := len(textutil.ReadLines(filepath.Join(wd, "subs.txt")))
	resolved := len(textutil.ReadLines(filepath.Join(wd, "resolved.txt")))
	https := 0
	reachable := 0
	for _, h := range live {
		if h.Status > 0 {
			reachable++
		}
		if strings.HasPrefix(h.URL, "https://") {
			https++
		}
	}
	shots := screenshotCount(wd)
	deep := 0
	if textutil.FileExists(filepath.Join(wd, "nuclei.jsonl")) {
		deep = reachable
	}
	var b strings.Builder
	b.WriteString("| Stage | Count |\n|-------|------:|\n")
	fmt.Fprintf(&b, "| Discovered DNS names | %d |\n", subs)
	fmt.Fprintf(&b, "| Resolved | %d |\n", resolved)
	fmt.Fprintf(&b, "| HTTP/S services (probed) | %d |\n", len(live))
	fmt.Fprintf(&b, "| Reachable at test time | %d |\n", reachable)
	fmt.Fprintf(&b, "| Eligible for TLS checks (HTTPS) | %d |\n", https)
	fmt.Fprintf(&b, "| Eligible for header checks | %d |\n", reachable)
	fmt.Fprintf(&b, "| Deep-content scanned (nuclei) | %d |\n", deep)
	fmt.Fprintf(&b, "| Screenshotted | %d |\n", shots)
	b.WriteString("\n_Discovery coverage (top rows) is distinct from security-test coverage (control ledger). A control ran on the **Eligible** population for that control, not on every discovered name._")
	return b.String()
}

// renderCapabilityMatrix states which attack classes were meaningfully exercised
// and which were out of scope, so "tested" is never read as "everything tested".
func renderCapabilityMatrix(deep bool, adversarial bool) string {
	deepCov := "Not run"
	deepRes := "Deep phase not selected"
	if deep {
		deepCov, deepRes = "Medium", "nuclei ruleset executed (pattern coverage only, not exhaustive)"
	}
	rows := [][3]string{
		{"Asset / attack-surface discovery", "High — CT / DNS / OSINT", "Completed"},
		{"TLS / transport posture", "High — active protocol+cipher negotiation", "Completed"},
		{"Security headers (HSTS/CSP/XFO/nosniff)", "High — direct response inspection", "Completed"},
		{"Unauthenticated operational exposure", "High — endpoint discovery + content classifier", "Completed"},
		{"Cross-origin policy (CORS)", "Medium — unauthenticated origin reflection + differential Origin matrix", "Completed"},
		{"Component / version CVE correlation", "Low — banner-inferred, OSV lookup", "Leads only (unvalidated)"},
		{"Known-pattern vulnerability templates (nuclei)", deepCov, deepRes},
		advRow("SSRF (out-of-band)", "OAST-validated canary callback", adversarial),
		advRow("Authorization-bypass variants", "read-only header/path/method variants", adversarial),
		advRow("Open redirect / arithmetic SSTI", "harmless exploit primitives", adversarial),
		advRow("OAuth/OIDC / identity surface", "well-known discovery + endpoint model", adversarial),
		advRow("Cloud object-storage exposure", "S3/GCS/Azure anonymous-listing enumeration", adversarial),
		advRow("API semantics (OpenAPI/GraphQL)", "schema + introspection + verbose-error", adversarial),
		{"BOLA / IDOR / business logic", "None — requires credentials (authorized-exploit)", "Not tested"},
	}
	var b strings.Builder
	b.WriteString("| Attack class | Coverage / method | Result |\n|--------------|-------------------|--------|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r[0], r[1], r[2])
	}
	b.WriteString("\n_\"Not tested\" classes are explicit non-coverage, not implied passes. Authenticated, destructive, and application-logic testing require a separate authorized engagement._")
	return b.String()
}

// screenshotCount is the single source of truth for how many page screenshots a
// run captured: a recursive count of non-empty .png files under the screenshots
// tree (httpx nests them as screenshots/screenshot/<host>/<hash>.png). Every
// place that reports a screenshot count uses this, and the report linter asserts
// they all agree.
func screenshotCount(wd string) int {
	root := filepath.Join(wd, "screenshots")
	n := 0
	filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), ".png") && info.Size() > 0 {
			n++
		}
		return nil
	})
	return n
}

// advRow marks an attack class covered when the adversarial profile ran, else
// explicit non-coverage — so "tested" never over-claims.
func advRow(name, method string, adversarial bool) [3]string {
	if adversarial {
		return [3]string{name, "Medium — " + method, "Completed (adversarial-readonly)"}
	}
	return [3]string{name, "None — safe-active profile", "Not tested"}
}
