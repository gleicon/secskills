package main

import (
	"crypto/sha256"
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
	for i := range findings {
		ensureEvidenceFields(&findings[i])
	}
	applyOverrides(target, findings)
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
        <div class="doctype">%s</div>
        <h1>%s</h1>
        <div class="cover-sub">External, unauthenticated, non-destructive — attack-surface &amp; vulnerability assessment (no exploitation/authenticated phase)</div>
      </div>
      <table class="cover-meta">
        <tr><td>Report date</td><td>%s</td></tr>
        <tr><td>Engagement type</td><td>External black-box — non-destructive</td></tr>
        <tr><td>Assessor</td><td>secskills v%s (automated assessment engine)</td></tr>
        <tr><td>Classification</td><td>Confidential — Authorized Recipients Only</td></tr>
        <tr><td>Report version</td><td>1.0</td></tr>
      </table>
      <div class="cover-foot">Distribute on a need-to-know basis over encrypted channels. This document contains sensitive security findings.</div>
    </section>`, esc(deliverableTitle(findings)), esc(target), date, version)

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
	w(`<div class="heat-cell total"><div class="hc-n">%d</div><div class="hc-l">OBSERVATIONS</div></div></div>`, total)
	w(`<h3>Root issues (observations collapsed)</h3><div class="rem">%s</div>`, mdBulletsToHTML(rootIssues(findings)))

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
      <tr><td>Provenance of tested hosts</td><td>All tested hosts are subdomains of the authorized apex, discovered via passive DNS / certificate transparency</td></tr>
      <tr><td>Authorization</td><td>%s</td></tr>
      <tr><td>Authenticated testing</td><td>%s</td></tr>
      <tr><td>Out of scope</td><td>Denial-of-service; social engineering; physical; destructive exploitation; cross-domain pivots (reported separately, require scope confirmation)</td></tr>
      </tbody></table></section>`, esc(target), esc(scopeAuthLine(target)), authLabel(authStatus))

	// ---- Coverage & capability ----
	deepRun := fileExists(filepath.Join(wd, "nuclei.jsonl")) || dirNonEmpty(filepath.Join(wd, "screenshots"))
	w(`<section class="page"><h2>2b. Coverage &amp; Capability</h2>
      <h3>Assessment coverage funnel</h3><div class="rem">%s</div>
      <h3>Assessment capability matrix</h3><div class="rem">%s</div></section>`,
		mdBulletsToHTML(renderCoverageFunnel(wd, live)), mdBulletsToHTML(renderCapabilityMatrix(deepRun, readProfile(wd).adversarial())))

	// ---- Findings Summary ----
	w(`<section class="page"><h2>3. Findings Summary</h2>
      <table class="grid findings-tbl"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>Owner team</th></tr></thead><tbody>`)
	for i := range findings {
		f := &findings[i]
		if f.KBClass == "" {
			classify(f)
		}
		w(`<tr><td>F-%03d</td><td>%s</td><td><span class="pill sev-%s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			i+1, esc(truncateStr(displayTitle(f), 70)), strings.ToLower(f.Severity), f.Severity, esc(cvssScoreStr(f)), esc(owaspShort(f.OWASP)), esc(complianceFor(f.KBClass).Team))
	}
	w(`</tbody></table></section>`)

	// ---- Root Findings (observations collapsed) ----
	w(`<section class="page"><h2>4. Root Findings</h2>
      <p>Observations are collapsed to root findings (one per control per asset-group). Per-observation detail and evidence ids are in the Observation Detail appendix.</p>`)
	ri := 0
	for _, rv := range collapseByRoot(findings) {
		ri++
		f := &rv.Rep
		c := complianceFor(f.KBClass)
		w(`<div class="finding">
          <div class="f-head"><span class="fid">R-%03d</span><span class="pill sev-%s">%s</span><h3>%s</h3></div>
          <table class="grid f-meta"><tbody>
          <tr><td>Affected endpoints</td><td>%d</td></tr>
          <tr><td>Confidence / Validation / State</td><td>%s / %s / %s</td></tr>
          <tr><td>OWASP / CWE</td><td>%s / %s</td></tr>
          <tr><td>Detector</td><td><code>%s</code></td></tr>
          <tr><td>Control (detector)</td><td><code>%s</code></td></tr>
          <tr><td>CVSS v3.1</td><td><code>%s</code></td></tr>`,
			ri, strings.ToLower(f.Severity), f.Severity, esc(rootTitleDisplay(f)),
			len(rv.Assets), esc(orDash(f.Confidence)), esc(orDash(f.Validation)), esc(orDash(f.State)),
			esc(f.OWASP), esc(f.CWE), esc(detectorIDFor(f)), esc(detectorIDFor(f)), esc(cvssString(f)))
		if f.PotentialSeverity != "" {
			w(`<tr><td>Potential severity (if validated)</td><td>%s — %s</td></tr>`, esc(f.PotentialSeverity), esc(f.EscalationCondition))
		}
		if len(rv.EvRefs) > 0 {
			w(`<tr><td>Evidence objects</td><td><code>%s</code></td></tr>`, esc(strings.Join(capList(rv.EvRefs, 12), ", ")))
		}
		if note := renderOverrideNote(f); note != "" {
			w(`<tr><td>Adjudication</td><td>%s</td></tr>`, esc(note))
		}
		w(`<tr><td>Remediation SLA</td><td>%s</td></tr>
          <tr><td>SOC 2 / ISO / PCI</td><td>%s / %s / %s</td></tr>
          <tr><td>Owning team</td><td>%s</td></tr>
          </tbody></table>`, esc(slaFor(f.Severity)), esc(c.SOC2), esc(c.ISO), esc(c.PCI), esc(c.Team))
		w(`<div class="f-body"><p><b>Affected endpoints.</b> %s</p>`, esc(strings.Join(capList(rv.Assets, 12), ", ")))
		w(`<p><b>Business risk.</b> %s</p>`, esc(businessRiskFor(f)))
		w(`<p><b>Severity rationale.</b> %s</p>`, mdBulletsToHTML(severityJustification(f)))
		w(`<p><b>Technical impact.</b> %s</p>`, esc(displayImpact(f)))
		if f.ObservedEvidence != "" {
			w(`<p><b>Representative observed evidence.</b></p><pre>%s</pre>`, esc(f.ObservedEvidence))
		}
		if rem := remediationByType(f); strings.TrimSpace(rem) != "" {
			w(`<p><b>Remediation.</b></p><div class="rem">%s</div></div></div>`, mdBulletsToHTML(rem))
		} else {
			w(`<p><b>Remediation.</b> None required (negative evidence / informational).</p></div></div>`)
		}
	}
	w(`<h3>Observation Detail</h3><div class="rem">%s</div>`, mdBulletsToHTML(renderObservationAppendix(findings)))
	w(`</section>`)

	// ---- Attack narrative ----
	w(`<section class="page"><h2>5. Attack Narrative</h2><p>%s</p>
      <h3>Attack-path exploration</h3><div class="rem">%s</div>
      <h3>Runtime planner attack-graph</h3><div class="rem">%s</div>
      <h3>Adversarial control ledger</h3><div class="rem">%s</div>
      <h3>Human red-team queue</h3><div class="rem">%s</div></section>`,
		esc(attackNarrative(findings, live, subs)),
		mdBulletsToHTML(renderAttackGraph(findings, readProfile(wd))),
		mdBulletsToHTML(renderPlannerGraph(wd)),
		mdBulletsToHTML(renderAdversarialLedger(findings, live, wd, registrableDomain(hostOf(target)), subs)),
		mdBulletsToHTML(renderHumanQueue(findings)))
	w(`<section class="page"><h2>Edge &amp; Defense Map (CDN / WAF / origin looking-glass)</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(renderEdgeMap(wd, target)))

	// ---- Compliance matrix ----
	w(`<section class="page"><h2>6. Compliance Coverage Matrix</h2>
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
	w(`<p>Raw data (subdomains, live services, findings JSON, Shodan OSINT, nuclei output) accompanies this report in <code>data/</code> for team distribution and re-testing (<code>secskills report --retest %s</code>). Ticket export: <code>secskills tickets %s</code>.</p>`, esc(target), esc(target))
	w(`</section>`)

	// ---- Appendix B — Cleanup log (non-destructive attestation) ----
	w(`<section class="page"><h2>Appendix B — Tools &amp; Cleanup Log</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(appendices(wd, authStatus)))

	// ---- Root-cause clustering, scorecard, evidence index, rubric ----
	w(`<section class="page"><h2>Root-Cause Clustering (shared configuration)</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(clusterRootIssues(findings, live)))
	w(`<section class="page"><h2>Detector Quality Scorecard</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(renderScorecard()))
	w(`<section class="page"><h2>Evidence Object Index</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(renderEvidenceIndex(wd)))
	w(`<section class="page"><h2>Severity Rubric (independent of CVSS)</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(severityRubric()))

	// ---- Control Test Ledger (negative evidence) ----
	w(`<section class="page"><h2>Control Test Ledger</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(renderLedger(live, findings)))

	// ---- Run Attestation (binds report to an exact run) ----
	w(`<section class="page"><h2>Run Attestation</h2><div class="rem">%s</div></section>`,
		mdBulletsToHTML(renderAttestation(wd)))

	sum := sha256.Sum256([]byte(b.String()))
	w(`<footer class="doc-foot">secskills v%s — Confidential — generated %s — Report SHA-256 %x</footer>`, version, date, sum)
	w(`</body></html>`)
	return b.String()
}

// mdBulletsToHTML renders a small markdown excerpt (bullets + inline code) to
// safe HTML for the report. Escapes everything, then applies minimal formatting.
func mdBulletsToHTML(md string) string {
	var b strings.Builder
	inList := false
	esc := html.EscapeString
	code := func(s string) string {
		for strings.Count(s, "`") >= 2 {
			i := strings.Index(s, "`")
			j := strings.Index(s[i+1:], "`") + i + 1
			s = s[:i] + "\x00" + esc(s[i+1:j]) + "\x01" + s[j+1:]
		}
		s = esc(s)
		s = strings.ReplaceAll(s, "\x00", "<code>")
		s = strings.ReplaceAll(s, "\x01", "</code>")
		return s
	}
	inTable := false
	for _, line := range strings.Split(md, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		// pipe table
		if strings.HasPrefix(t, "|") {
			cells := strings.Split(strings.Trim(t, "|"), "|")
			if len(cells) > 0 && strings.Contains(cells[0], "---") {
				continue // separator row
			}
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			if !inTable {
				b.WriteString(`<table class="grid"><tbody>`)
				inTable = true
			}
			b.WriteString("<tr>")
			for _, cell := range cells {
				b.WriteString("<td>" + code(strings.TrimSpace(cell)) + "</td>")
			}
			b.WriteString("</tr>")
			continue
		}
		if inTable {
			b.WriteString("</tbody></table>")
			inTable = false
		}
		if strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* ") {
			if !inList {
				b.WriteString("<ul>")
				inList = true
			}
			b.WriteString("<li>" + code(t[2:]) + "</li>")
		} else {
			if inList {
				b.WriteString("</ul>")
				inList = false
			}
			b.WriteString("<p>" + code(t) + "</p>")
		}
	}
	if inList {
		b.WriteString("</ul>")
	}
	if inTable {
		b.WriteString("</tbody></table>")
	}
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
	compromise := "No critical compromise path was demonstrated during this unauthenticated, non-destructive assessment."
	if c["CRITICAL"] > 0 {
		compromise = "A critical-severity condition was identified requiring immediate manual validation."
	}
	return fmt.Sprintf("%s We enumerated %d subdomains of %s and identified %d externally reachable services, recording %d "+
		"observations (%d high, %d medium, %d low/info). The broader pattern is inconsistent edge hardening — chiefly legacy TLS and "+
		"HTTP security-header configuration applied unevenly. Most individual observations do not independently represent a material "+
		"compromise path and are best addressed as platform/edge configuration issues (see Root issues) rather than application-by-application "+
		"vulnerabilities. A small number warrant immediate manual validation. Findings carry explicit Confidence and Validation states; those "+
		"marked version-inferred or config-inferred are leads pending validation, not confirmed vulnerabilities. Exploitation and authenticated "+
		"testing were out of scope.",
		compromise, subs, target, live, total, c["HIGH"]+c["CRITICAL"], c["MEDIUM"], c["LOW"]+c["INFORMATIONAL"])
}

// cmdReportHTML / PDF entrypoints are wired via cmdReport flags.
func writeHTMLReport(target, wd, output string) error {
	fs := loadOrLatest(target, wd)
	if err := enforceReportLint(target, wd, normalizedForLint(target, wd, fs)); err != nil {
		return err
	}
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
	if err := enforceReportLint(target, wd, normalizedForLint(target, wd, loadOrLatest(target, wd))); err != nil {
		return err
	}
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
