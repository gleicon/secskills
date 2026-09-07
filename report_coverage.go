package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// renderCoverageFunnel makes discovery coverage distinct from security coverage
// (audit item: "40 services tested" must not be read as "everything tested").
// Numbers come from the pipeline artifacts in the workdir.
func renderCoverageFunnel(wd string, live []LiveHost) string {
	subs := len(readLines(filepath.Join(wd, "subs.txt")))
	resolved := len(readLines(filepath.Join(wd, "resolved.txt")))
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
	if fileExists(filepath.Join(wd, "nuclei.jsonl")) {
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
func renderCapabilityMatrix(deep bool) string {
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
		{"Cross-origin policy (CORS)", "Medium — unauthenticated origin reflection", "Completed"},
		{"Component / version CVE correlation", "Low — banner-inferred, OSV lookup", "Leads only (unvalidated)"},
		{"Known-pattern vulnerability templates (nuclei)", deepCov, deepRes},
		{"SSRF / injection exploitation", "None — exploitation prohibited", "Not tested"},
		{"BOLA / IDOR / authz logic", "None — authenticated testing out of scope", "Not tested"},
		{"OAuth/OIDC / identity surface", "None (this pass)", "Not tested"},
		{"Cloud object-storage exposure", "None (this pass)", "Not tested"},
		{"API semantics (OpenAPI/GraphQL)", "None (this pass)", "Not tested"},
	}
	var b strings.Builder
	b.WriteString("| Attack class | Coverage / method | Result |\n|--------------|-------------------|--------|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r[0], r[1], r[2])
	}
	b.WriteString("\n_\"Not tested\" classes are explicit non-coverage, not implied passes. Authenticated, destructive, and application-logic testing require a separate authorized engagement._")
	return b.String()
}

func dirCount(dir string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() {
			n++
		}
	}
	return n
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
