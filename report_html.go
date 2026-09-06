package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// renderHTMLReport produces a professional, print-optimized HTML pentest report
// (big-4 consulting style) suitable for PDF export and SOC 2 / ISO / PCI evidence.
// Sections carry page breaks; findings map to compliance controls and owning teams
// so a CISO can split evidence and remediation across groups.
func renderHTMLReport(target, wd string, findings []Finding) string {
	sortFindings(findings)
	counts := severityCounts(findings)
	live := liveHosts(wd)
	subs := readLines(filepath.Join(wd, "subs.txt"))
	authStatus := strings.TrimSpace(readFileOr(filepath.Join(wd, "auth-status.txt"), "not-available"))
	ssStatus := strings.TrimSpace(readFileOr(filepath.Join(wd, "screenshots-status.txt"), "not-available"))
	date := nowRFC()[:10]

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	esc := html.EscapeString

	w(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	w(`<title>Penetration Test Report — %s</title>`, esc(target))
	w(`<style>%s</style></head><body>`, reportCSS)

	// ---- Cover ----
	w(`<section class="cover">
      <div class="cover-top"><div class="brand">secskills</div><div class="classif">CONFIDENTIAL</div></div>
      <div class="cover-mid">
        <div class="doctype">External Penetration Test Report</div>
        <h1>%s</h1>
        <div class="cover-sub">OWASP-aligned external security assessment</div>
      </div>
      <table class="cover-meta">
        <tr><td>Report date</td><td>%s</td></tr>
        <tr><td>Engagement type</td><td>External black-box — non-destructive</td></tr>
        <tr><td>Assessor</td><td>secskills v%s (automated assessment engine)</td></tr>
        <tr><td>Classification</td><td>Confidential — Authorized Recipients Only</td></tr>
        <tr><td>Report version</td><td>1.0</td></tr>
      </table>
      <div class="cover-foot">Distribute on a need-to-know basis over encrypted channels. This document contains sensitive security findings.</div>
    </section>`, esc(target), date, version)

	// ---- Document control ----
	w(`<section class="page"><h2>Document Control</h2>
      <table class="grid"><thead><tr><th>Field</th><th>Detail</th></tr></thead><tbody>
      <tr><td>Prepared for</td><td>Security / CISO office — %s</td></tr>
      <tr><td>Prepared by</td><td>secskills automated assessment</td></tr>
      <tr><td>Report status</td><td>Final</td></tr>
      <tr><td>Confidentiality</td><td>Confidential — do not distribute outside authorized recipients</td></tr>
      <tr><td>Frameworks referenced</td><td>OWASP Top 10 2021 (Web), OWASP Mobile Top 10 2024, OWASP Top 10 for LLM Apps 2025, OWASP WSTG, CWE, OSV, MITRE ATT&amp;CK</td></tr>
      <tr><td>Compliance mapping</td><td>SOC 2 (Trust Services Criteria), ISO/IEC 27001:2022 Annex A, PCI-DSS 4.0</td></tr>
      </tbody></table>
      <p class="note">Compliance control references are provided to assist audit evidence collection (e.g., SOC 2). They indicate the criteria a finding is relevant to; they are not a statement of audit opinion.</p></section>`, esc(target))

	// ---- Executive Summary ----
	total := len(findings)
	w(`<section class="page"><h2>1. Executive Summary</h2>`)
	w(`<p>%s</p>`, esc(execNarrativeHTML(target, counts, len(subs), len(live))))
	w(`<h3>Risk profile</h3><div class="heat">`)
	for _, s := range sevOrder {
		if s == "INFORMATIONAL" && counts[s] == 0 {
			continue
		}
		w(`<div class="heat-cell sev-%s"><div class="hc-n">%d</div><div class="hc-l">%s</div></div>`, strings.ToLower(s), counts[s], s)
	}
	w(`<div class="heat-cell total"><div class="hc-n">%d</div><div class="hc-l">TOTAL</div></div></div>`, total)

	w(`<h3>Key findings</h3><ul class="keys">`)
	kn := 0
	for i := range findings {
		if findings[i].Severity == "HIGH" || findings[i].Severity == "CRITICAL" {
			w(`<li><span class="pill sev-%s">%s</span> %s <span class="host">%s</span></li>`,
				strings.ToLower(findings[i].Severity), findings[i].Severity, esc(findings[i].Title), esc(findings[i].Host))
			kn++
		}
		if kn >= 8 {
			break
		}
	}
	if kn == 0 {
		w(`<li>No high or critical findings; posture is dominated by hardening gaps (see §5).</li>`)
	}
	w(`</ul>`)
	w(`<h3>Assessment coverage</h3><table class="grid"><tbody>
      <tr><td>Subdomains enumerated</td><td>%d</td></tr>
      <tr><td>Live services tested</td><td>%d</td></tr>
      <tr><td>Authenticated testing</td><td>%s</td></tr>
      <tr><td>Visual evidence (screenshots)</td><td>%s</td></tr>
      </tbody></table></section>`, len(subs), len(live), authLabel(authStatus), esc(ssStatus))

	// ---- Methodology & Scope ----
	w(`<section class="page"><h2>2. Methodology &amp; Scope</h2>
      <p>The assessment followed a phased, non-destructive external methodology aligned to OWASP WSTG and PTES:</p>
      <ol>
        <li><b>Passive reconnaissance</b> — subdomain enumeration, certificate transparency, and Shodan OSINT (IP space, ASN/org, ports, product/version, third-party SaaS).</li>
        <li><b>Resolution &amp; live-host discovery</b> — DNS resolution then HTTP/S probing of resolved hosts.</li>
        <li><b>Active testing</b> (rate-limited, scope-confined) — security headers, TLS posture, unauthenticated exposure (baseline-differential), and component CVE lookup (OSV).</li>
        <li><b>Deep phase</b> — template scanning (nuclei), TLS cipher/protocol enumeration (sslscan), content discovery, and screenshots.</li>
        <li><b>Classification</b> — each finding mapped to OWASP, CWE, an OWASP Cheat Sheet, and SOC 2 / ISO / PCI controls.</li>
      </ol>
      <table class="grid"><thead><tr><th>Scope item</th><th>Value</th></tr></thead><tbody>
      <tr><td>In-scope apex</td><td>%s</td></tr>
      <tr><td>Rules of engagement</td><td>Non-destructive; rate-limited; scope-confined to the apex and subdomains</td></tr>
      <tr><td>Authenticated testing</td><td>%s</td></tr>
      <tr><td>Out of scope</td><td>Denial-of-service; social engineering; physical; destructive exploitation</td></tr>
      </tbody></table></section>`, esc(target), authLabel(authStatus))

	// ---- Findings Summary ----
	w(`<section class="page"><h2>3. Findings Summary</h2>
      <table class="grid findings-tbl"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>Owner team</th></tr></thead><tbody>`)
	for i := range findings {
		f := &findings[i]
		if f.KBClass == "" {
			classify(f)
		}
		w(`<tr><td>F-%03d</td><td>%s</td><td><span class="pill sev-%s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			i+1, esc(truncateStr(f.Title, 70)), strings.ToLower(f.Severity), f.Severity, cvssBand(f.Severity), esc(owaspShort(f.OWASP)), esc(complianceFor(f.KBClass).Team))
	}
	w(`</tbody></table></section>`)

	// ---- Detailed Findings ----
	w(`<section class="page"><h2>4. Detailed Findings</h2>`)
	for i := range findings {
		f := &findings[i]
		c := complianceFor(f.KBClass)
		w(`<div class="finding">
          <div class="f-head"><span class="fid">F-%03d</span><span class="pill sev-%s">%s</span><h3>%s</h3></div>
          <table class="grid f-meta"><tbody>
          <tr><td>Affected asset</td><td>%s</td></tr>
          <tr><td>OWASP</td><td>%s</td></tr>
          <tr><td>CWE</td><td>%s</td></tr>
          <tr><td>CVSS v3.1 (indicative band)</td><td>%s</td></tr>`,
			i+1, strings.ToLower(f.Severity), f.Severity, esc(f.Title),
			esc(f.Host), esc(f.OWASP), esc(f.CWE), cvssBand(f.Severity))
		if len(f.CVEs) > 0 {
			w(`<tr><td>CVEs (OSV)</td><td>%s</td></tr>`, esc(strings.Join(f.CVEs, ", ")))
		}
		w(`<tr><td>SOC 2 (TSC)</td><td>%s</td></tr>
          <tr><td>ISO/IEC 27001:2022</td><td>%s</td></tr>
          <tr><td>PCI-DSS 4.0</td><td>%s</td></tr>
          <tr><td>Owning team</td><td>%s</td></tr>
          </tbody></table>`, esc(c.SOC2), esc(c.ISO), esc(c.PCI), esc(c.Team))
		w(`<div class="f-body"><p><b>Impact.</b> %s</p>`, esc(impactFor(f.KBClass)))
		if f.EvidenceCmd != "" {
			w(`<p><b>Evidence (reproduce).</b></p><pre>%s</pre>`, esc(f.EvidenceCmd))
		}
		w(`<p><b>Remediation.</b> %s Reference: OWASP Cheat Sheet <code>%s</code>; secure-code recipe available.</p></div></div>`,
			esc(remediationFor(f.KBClass)), esc(f.KBClass))
	}
	w(`</section>`)

	// ---- Compliance matrix ----
	w(`<section class="page"><h2>5. Compliance Coverage Matrix</h2>
      <p>Findings grouped by control domain — usable as an evidence index for SOC 2 / ISO 27001 / PCI-DSS audits.</p>
      <table class="grid"><thead><tr><th>Control domain</th><th>Findings</th><th>SOC 2</th><th>Owner</th></tr></thead><tbody>`)
	byClass := map[string]int{}
	for _, f := range findings {
		byClass[f.KBClass]++
	}
	for _, cls := range []string{"config-exposure", "crypto-secrets", "components-supply-chain", "access-control", "auth-session", "injection", "ssrf-xxe", "logging-monitoring"} {
		if byClass[cls] == 0 {
			continue
		}
		c := complianceFor(cls)
		w(`<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>`, cls, byClass[cls], esc(c.SOC2), esc(c.Team))
	}
	w(`</tbody></table></section>`)

	// ---- Evidence / screenshot index ----
	w(`<section class="page"><h2>Appendix A — Evidence Index</h2>`)
	if strings.HasPrefix(ssStatus, "not-available") {
		w(`<p>Screenshots: <b>not available</b> (%s).</p>`, esc(strings.TrimPrefix(ssStatus, "not-available")))
	} else {
		w(`<p>Page screenshots (%s) are provided in <code>screenshots/</code>, referenced by host. Findings-to-evidence mapping is via the affected-asset field of each finding.</p>`, esc(ssStatus))
	}
	w(`<p>Raw data (subdomains, live services, findings JSON, Shodan OSINT, nuclei output) accompanies this report in <code>data/</code> for team distribution and re-testing (<code>secskills report --retest %s</code>).</p>`, esc(target))
	w(`</section>`)

	w(`<footer class="doc-foot">secskills v%s — Confidential — generated %s</footer>`, version, date)
	w(`</body></html>`)
	return b.String()
}

func authLabel(status string) string {
	if status == "provided" {
		return "Performed (credentials supplied)"
	}
	return "Not available — no credentials supplied"
}

func execNarrativeHTML(target string, c map[string]int, subs, live int) string {
	total := 0
	for _, v := range c {
		total += v
	}
	level := "LOW-to-MODERATE"
	switch {
	case c["CRITICAL"] > 0:
		level = "CRITICAL"
	case c["HIGH"] >= 3:
		level = "HIGH"
	case c["HIGH"] > 0:
		level = "MODERATE-to-HIGH"
	}
	return fmt.Sprintf("This report presents the results of an external penetration test of %s. "+
		"The assessment enumerated %d subdomains and tested %d live services, identifying %d findings "+
		"(%d high/critical, %d medium, %d low). Overall external risk is assessed as %s. The findings are "+
		"predominantly hardening and transport-security gaps, alongside a focused set of higher-impact issues "+
		"(outdated components with known CVEs and unauthenticated exposure of operational endpoints). "+
		"Each finding is mapped to OWASP, CWE, and SOC 2 / ISO 27001 / PCI-DSS controls, and assigned an owning "+
		"team to support remediation across groups.",
		target, subs, live, total, c["HIGH"]+c["CRITICAL"], c["MEDIUM"], c["LOW"], level)
}

// cmdReportHTML / PDF entrypoints are wired via cmdReport flags.
func writeHTMLReport(target, wd, output string) error {
	report := renderHTMLReport(target, wd, loadOrLatest(target, wd))
	if output == "" {
		output = target + "_report.html"
	}
	if err := os.WriteFile(output, []byte(report), 0o644); err != nil {
		return err
	}
	fmt.Printf("HTML report: %s\n", output)
	return nil
}

func writePDFReport(target, wd, output string) error {
	if output == "" {
		output = target + "_report.pdf"
	}
	htmlPath := output + ".tmp.html"
	if err := os.WriteFile(htmlPath, []byte(renderHTMLReport(target, wd, loadOrLatest(target, wd))), 0o644); err != nil {
		return err
	}
	defer os.Remove(htmlPath)
	chrome := chromePath()
	if chrome == "" {
		return fmt.Errorf("PDF needs headless Chrome/Chromium (not found) — HTML written to %s; convert with your browser's Print to PDF", htmlPath)
	}
	abs, _ := filepath.Abs(htmlPath)
	outAbs, _ := filepath.Abs(output)
	cmd := exec.Command(chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
		"--print-to-pdf="+outAbs, "file://"+abs)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chrome print-to-pdf failed: %v\n%s", err, out)
	}
	fmt.Printf("PDF report: %s\n", output)
	return nil
}

func chromePath() string {
	for _, b := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	if p := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; fileExists(p) {
		return p
	}
	return ""
}

func loadOrLatest(target, wd string) []Finding {
	f := loadWorkFindings(wd)
	if len(f) > 0 {
		return f
	}
	if b, err := os.ReadFile(filepath.Join(storeDir(target), "latest")); err == nil {
		var run Run
		if json.Unmarshal(b, &run) == nil {
			return run.Findings
		}
	}
	return nil
}
