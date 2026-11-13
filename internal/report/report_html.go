package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gleicon/secskills"
	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
)

// renderHTMLReport produces a professional, print-optimized HTML pentest report
// (big-4 consulting style) suitable for PDF export and SOC 2 / ISO / PCI evidence.
//
// Rendering uses html/template: every target-derived value is an auto-escaped
// {{.}} field, so HTML injection cannot happen by forgetting to escape. The only
// values rendered as trusted template.HTML are fragments produced by
// mdBulletsToHTML, which escapes its own input.

type htmlHeat struct {
	Sev, SevLower string
	N             int
}
type htmlKey struct {
	SevLower, Sev, Title, Host string
}
type htmlSummary struct {
	ID, Title, SevLower, Sev, CVSS, OWASP, Team string
}
type htmlCard struct {
	ID, SevLower, Sev, Title       string
	Affected                       int
	Confidence, Validation, State  string
	OWASP, CWE, Detector, CVSS     string
	PotentialSeverity, Escalation  string
	EvRefs, Adjudication           string
	SLA, SOC2, ISO, PCI, Team      string
	AffectedList, BusinessRisk     string
	TechImpact, ObservedEvidence   string
	SeverityRationale, Remediation template.HTML
	RemediationNone                bool
}
type htmlComp struct {
	Class      string
	N          int
	SOC2, Team string
}

type htmlVM struct {
	Deliverable, Target, Date, Version string
	ExecNarr                           string
	Heat                               []htmlHeat
	Total                              int
	RootIssues                         template.HTML
	KeyFindings                        []htmlKey
	Subs, Live                         int
	AuthLabel, SSStatus, SSStatusTrim  string
	SSNotAvailable                     bool
	ScopeAuthLine                      string
	Coverage, Capability               template.HTML
	Summary                            []htmlSummary
	RootCards                          []htmlCard
	ObservationDetail                  template.HTML
	AttackNarr                         string
	AttackGraph, PlannerGraph          template.HTML
	GraphMetrics                       template.HTML
	AdvLedger, HumanQueue, EdgeMap     template.HTML
	Compliance                         []htmlComp
	Appendices, Clustering, Scorecard  template.HTML
	EvidenceIndex, Rubric, Ledger      template.HTML
	Attestation                        template.HTML
}

func renderHTMLReport(target, wd string, findings []finding.Finding) string {
	finding.SortFindings(findings)
	counts := severityCounts(findings)
	live := tooling.LiveHosts(wd)
	for i := range findings {
		finding.EnsureEvidenceFields(&findings[i])
	}
	finding.ApplyOverrides(target, findings)
	subs := textutil.ReadLines(filepath.Join(wd, "subs.txt"))
	authStatus := strings.TrimSpace(textutil.ReadFileOr(filepath.Join(wd, "auth-status.txt"), "not-available"))
	ssStatus := strings.TrimSpace(textutil.ReadFileOr(filepath.Join(wd, "screenshots-status.txt"), "not-available"))
	deepRun := textutil.FileExists(filepath.Join(wd, "nuclei.jsonl")) || dirNonEmpty(filepath.Join(wd, "screenshots"))
	adversarial := finding.ReadProfile(wd).Adversarial()

	md := func(s string) template.HTML { return template.HTML(mdBulletsToHTML(s)) }

	vm := htmlVM{
		Deliverable: deliverableTitle(findings), Target: target, Date: finding.NowRFC()[:10], Version: secskills.Version,
		ExecNarr: execNarrativeHTML(target, counts, len(subs), len(live)),
		Total:    len(findings), Subs: len(subs), Live: len(live),
		AuthLabel: authLabel(authStatus), SSStatus: ssStatus,
		SSNotAvailable:    strings.HasPrefix(ssStatus, "not-available"),
		SSStatusTrim:      strings.TrimPrefix(ssStatus, "not-available"),
		ScopeAuthLine:     finding.ScopeAuthLine(target),
		RootIssues:        md(rootIssues(findings)),
		Coverage:          md(renderCoverageFunnel(wd, live)),
		Capability:        md(renderCapabilityMatrix(deepRun, adversarial)),
		ObservationDetail: md(renderObservationAppendix(findings)),
		AttackNarr:        finding.AttackNarrative(findings, live, subs),
		AttackGraph:       md(engine.RenderAttackGraph(findings, finding.ReadProfile(wd))),
		PlannerGraph:      md(engine.RenderPlannerGraph(wd)),
		GraphMetrics:      md(engine.RenderGraphMetrics(wd, findings)),
		AdvLedger:         md(engine.RenderAdversarialLedger(findings, live, wd, engine.RegistrableDomain(netsec.HostOf(target)), subs)),
		HumanQueue:        md(engine.RenderHumanQueue(findings)),
		EdgeMap:           md(engine.RenderEdgeMap(wd, target)),
		Appendices:        md(finding.Appendices(wd, authStatus)),
		Clustering:        md(engine.ClusterRootIssues(findings, live)),
		Scorecard:         md(engine.RenderScorecard()),
		EvidenceIndex:     md(finding.RenderEvidenceIndex(wd)),
		Rubric:            md(finding.SeverityRubric()),
		Ledger:            md(finding.RenderLedger(live, findings)),
		Attestation:       md(finding.RenderAttestation(wd)),
	}
	for _, s := range sevOrder {
		if s == "INFORMATIONAL" && counts[s] == 0 {
			continue
		}
		vm.Heat = append(vm.Heat, htmlHeat{Sev: s, SevLower: strings.ToLower(s), N: counts[s]})
	}
	for i := range findings {
		f := &findings[i]
		if (f.Severity == "HIGH" || f.Severity == "CRITICAL") && len(vm.KeyFindings) < 8 {
			vm.KeyFindings = append(vm.KeyFindings, htmlKey{
				SevLower: strings.ToLower(f.Severity), Sev: f.Severity, Title: f.Title, Host: f.Host,
			})
		}
	}
	for i := range findings {
		f := &findings[i]
		if f.KBClass == "" {
			finding.Classify(f)
		}
		vm.Summary = append(vm.Summary, htmlSummary{
			ID: fmt.Sprintf("F-%03d", i+1), Title: truncateStr(finding.DisplayTitle(f), 70),
			SevLower: strings.ToLower(f.Severity), Sev: f.Severity,
			CVSS: finding.CVSSScoreStr(f), OWASP: OwaspShort(f.OWASP), Team: finding.ComplianceFor(f.KBClass).Team,
		})
	}
	ri := 0
	for _, rv := range collapseByRoot(findings) {
		ri++
		f := &rv.Rep
		c := finding.ComplianceFor(f.KBClass)
		card := htmlCard{
			ID: fmt.Sprintf("R-%03d", ri), SevLower: strings.ToLower(f.Severity), Sev: f.Severity,
			Title: rootTitleDisplay(f), Affected: len(rv.Assets),
			Confidence: textutil.OrDash(f.Confidence), Validation: textutil.OrDash(f.Validation), State: textutil.OrDash(f.State),
			OWASP: f.OWASP, CWE: f.CWE, Detector: finding.DetectorIDFor(f), CVSS: finding.CVSSString(f),
			PotentialSeverity: f.PotentialSeverity, Escalation: f.EscalationCondition,
			Adjudication: finding.RenderOverrideNote(f),
			SLA:          finding.SLAFor(f.Severity), SOC2: c.SOC2, ISO: c.ISO, PCI: c.PCI, Team: c.Team,
			AffectedList: strings.Join(finding.CapList(rv.Assets, 12), ", "),
			BusinessRisk: finding.BusinessRiskFor(f), TechImpact: finding.DisplayImpact(f), ObservedEvidence: f.ObservedEvidence,
			SeverityRationale: md(finding.SeverityJustification(f)),
		}
		if len(rv.EvRefs) > 0 {
			card.EvRefs = strings.Join(finding.CapList(rv.EvRefs, 12), ", ")
		}
		if rem := finding.RemediationByType(f); strings.TrimSpace(rem) != "" {
			card.Remediation = md(rem)
		} else {
			card.RemediationNone = true
		}
		vm.RootCards = append(vm.RootCards, card)
	}
	byClass := map[string]int{}
	for _, f := range findings {
		byClass[f.KBClass]++
	}
	for _, cls := range []string{"config-exposure", "crypto-secrets", "components-supply-chain", "access-control", "auth-session", "injection", "ssrf-xxe", "logging-monitoring"} {
		if byClass[cls] == 0 {
			continue
		}
		cc := finding.ComplianceFor(cls)
		vm.Compliance = append(vm.Compliance, htmlComp{Class: cls, N: byClass[cls], SOC2: cc.SOC2, Team: cc.Team})
	}

	var body strings.Builder
	if err := reportTmpl.Execute(&body, vm); err != nil {
		return "<!doctype html><html><body>report template error: " + html.EscapeString(err.Error()) + "</body></html>"
	}
	// Report SHA-256 over the full body (mirrors the previous renderer, which
	// hashed everything written before the footer).
	sum := sha256.Sum256([]byte(body.String()))
	footer := fmt.Sprintf(`<footer class="doc-foot">secskills v%s — Confidential — generated %s — Report SHA-256 %x</footer></body></html>`,
		html.EscapeString(secskills.Version), html.EscapeString(vm.Date), sum)
	return body.String() + footer
}

// reportTmpl is the full report page (everything up to the signed footer, which
// renderHTMLReport appends after hashing the body). {{.}} auto-escapes; the rem
// blocks are trusted template.HTML from mdBulletsToHTML.
var reportTmpl = template.Must(template.New("report").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">` +
	`<title>Penetration Test Report — {{.Target}}</title><style>` + reportCSS + `</style></head><body>` +
	`<section class="cover">
  <div class="cover-top"><div class="brand">secskills</div><div class="classif">CONFIDENTIAL</div></div>
  <div class="cover-mid"><div class="doctype">{{.Deliverable}}</div><h1>{{.Target}}</h1>
    <div class="cover-sub">External, unauthenticated, non-destructive — attack-surface &amp; vulnerability assessment (no exploitation/authenticated phase)</div></div>
  <table class="cover-meta">
    <tr><td>Report date</td><td>{{.Date}}</td></tr>
    <tr><td>Engagement type</td><td>External black-box — non-destructive</td></tr>
    <tr><td>Assessor</td><td>secskills v{{.Version}} (automated assessment engine)</td></tr>
    <tr><td>Classification</td><td>Confidential — Authorized Recipients Only</td></tr>
    <tr><td>Report version</td><td>1.0</td></tr>
  </table>
  <div class="cover-foot">Distribute on a need-to-know basis over encrypted channels. This document contains sensitive security findings.</div>
</section>` +
	`<section class="page"><h2>Document Control</h2>
  <table class="grid"><thead><tr><th>Field</th><th>Detail</th></tr></thead><tbody>
  <tr><td>Prepared for</td><td>Security / CISO office — {{.Target}}</td></tr>
  <tr><td>Prepared by</td><td>secskills automated assessment</td></tr>
  <tr><td>Report status</td><td>Final</td></tr>
  <tr><td>Confidentiality</td><td>Confidential — do not distribute outside authorized recipients</td></tr>
  <tr><td>Frameworks referenced</td><td>OWASP Top 10 2021 (Web), OWASP Mobile Top 10 2024, OWASP Top 10 for LLM Apps 2025, OWASP WSTG, CWE, OSV, MITRE ATT&amp;CK</td></tr>
  <tr><td>Compliance mapping</td><td>SOC 2 (Trust Services Criteria), ISO/IEC 27001:2022 Annex A, PCI-DSS 4.0</td></tr>
  </tbody></table>
  <p class="note">Compliance control references are provided to assist audit evidence collection (e.g., SOC 2). They indicate the criteria a finding is relevant to; they are not a statement of audit opinion.</p></section>` +
	`<section class="page"><h2>1. Executive Summary</h2><p>{{.ExecNarr}}</p>
  <h3>Risk profile</h3><div class="heat">
  {{range .Heat}}<div class="heat-cell sev-{{.SevLower}}"><div class="hc-n">{{.N}}</div><div class="hc-l">{{.Sev}}</div></div>{{end}}
  <div class="heat-cell total"><div class="hc-n">{{.Total}}</div><div class="hc-l">OBSERVATIONS</div></div></div>
  <h3>Root issues (observations collapsed)</h3><div class="rem">{{.RootIssues}}</div>
  <h3>Key findings</h3><ul class="keys">
  {{range .KeyFindings}}<li><span class="pill sev-{{.SevLower}}">{{.Sev}}</span> {{.Title}} <span class="host">{{.Host}}</span></li>{{else}}<li>No high or critical findings; posture is dominated by hardening gaps (see §5).</li>{{end}}
  </ul>
  <h3>Assessment coverage</h3><table class="grid"><tbody>
  <tr><td>Subdomains enumerated</td><td>{{.Subs}}</td></tr>
  <tr><td>Live services tested</td><td>{{.Live}}</td></tr>
  <tr><td>Authenticated testing</td><td>{{.AuthLabel}}</td></tr>
  <tr><td>Visual evidence (screenshots)</td><td>{{.SSStatus}}</td></tr>
  </tbody></table></section>` +
	`<section class="page"><h2>2. Methodology &amp; Scope</h2>
  <p>The assessment followed a phased, non-destructive external methodology aligned to OWASP WSTG and PTES:</p>
  <ol>
    <li><b>Passive reconnaissance</b> — subdomain enumeration, certificate transparency, and Shodan OSINT (IP space, ASN/org, ports, product/version, third-party SaaS).</li>
    <li><b>Resolution &amp; live-host discovery</b> — DNS resolution then HTTP/S probing of resolved hosts.</li>
    <li><b>Active testing</b> (rate-limited, scope-confined) — security headers, TLS posture, unauthenticated exposure (baseline-differential), and component CVE lookup (OSV).</li>
    <li><b>Deep phase</b> — template scanning (nuclei), TLS cipher/protocol enumeration (sslscan), content discovery, and screenshots.</li>
    <li><b>Classification</b> — each finding mapped to OWASP, CWE, an OWASP Cheat Sheet, and SOC 2 / ISO / PCI controls.</li>
  </ol>
  <table class="grid"><thead><tr><th>Scope item</th><th>Value</th></tr></thead><tbody>
  <tr><td>In-scope apex</td><td>{{.Target}}</td></tr>
  <tr><td>Rules of engagement</td><td>Non-destructive; rate-limited; scope-confined to the apex and subdomains</td></tr>
  <tr><td>Provenance of tested hosts</td><td>All tested hosts are subdomains of the authorized apex, discovered via passive DNS / certificate transparency</td></tr>
  <tr><td>Authorization</td><td>{{.ScopeAuthLine}}</td></tr>
  <tr><td>Authenticated testing</td><td>{{.AuthLabel}}</td></tr>
  <tr><td>Out of scope</td><td>Denial-of-service; social engineering; physical; destructive exploitation; cross-domain pivots (reported separately, require scope confirmation)</td></tr>
  </tbody></table></section>` +
	`<section class="page"><h2>2b. Coverage &amp; Capability</h2>
  <h3>Assessment coverage funnel</h3><div class="rem">{{.Coverage}}</div>
  <h3>Assessment capability matrix</h3><div class="rem">{{.Capability}}</div></section>` +
	`<section class="page"><h2>3. Findings Summary</h2>
  <table class="grid findings-tbl"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CVSS</th><th>OWASP</th><th>Owner team</th></tr></thead><tbody>
  {{range .Summary}}<tr><td>{{.ID}}</td><td>{{.Title}}</td><td><span class="pill sev-{{.SevLower}}">{{.Sev}}</span></td><td>{{.CVSS}}</td><td>{{.OWASP}}</td><td>{{.Team}}</td></tr>{{end}}
  </tbody></table></section>` +
	`<section class="page"><h2>4. Root Findings</h2>
  <p>Observations are collapsed to root findings (one per control per asset-group). Per-observation detail and evidence ids are in the Observation Detail appendix.</p>
  {{range .RootCards}}<div class="finding">
    <div class="f-head"><span class="fid">{{.ID}}</span><span class="pill sev-{{.SevLower}}">{{.Sev}}</span><h3>{{.Title}}</h3></div>
    <table class="grid f-meta"><tbody>
    <tr><td>Affected endpoints</td><td>{{.Affected}}</td></tr>
    <tr><td>Confidence / Validation / State</td><td>{{.Confidence}} / {{.Validation}} / {{.State}}</td></tr>
    <tr><td>OWASP / CWE</td><td>{{.OWASP}} / {{.CWE}}</td></tr>
    <tr><td>Detector</td><td><code>{{.Detector}}</code></td></tr>
    <tr><td>Control (detector)</td><td><code>{{.Detector}}</code></td></tr>
    <tr><td>CVSS v3.1</td><td><code>{{.CVSS}}</code></td></tr>
    {{if .PotentialSeverity}}<tr><td>Potential severity (if validated)</td><td>{{.PotentialSeverity}} — {{.Escalation}}</td></tr>{{end}}
    {{if .EvRefs}}<tr><td>Evidence objects</td><td><code>{{.EvRefs}}</code></td></tr>{{end}}
    {{if .Adjudication}}<tr><td>Adjudication</td><td>{{.Adjudication}}</td></tr>{{end}}
    <tr><td>Remediation SLA</td><td>{{.SLA}}</td></tr>
    <tr><td>SOC 2 / ISO / PCI</td><td>{{.SOC2}} / {{.ISO}} / {{.PCI}}</td></tr>
    <tr><td>Owning team</td><td>{{.Team}}</td></tr>
    </tbody></table>
    <div class="f-body"><p><b>Affected endpoints.</b> {{.AffectedList}}</p>
    <p><b>Business risk.</b> {{.BusinessRisk}}</p>
    <p><b>Severity rationale.</b> {{.SeverityRationale}}</p>
    <p><b>Technical impact.</b> {{.TechImpact}}</p>
    {{if .ObservedEvidence}}<p><b>Representative observed evidence.</b></p><pre>{{.ObservedEvidence}}</pre>{{end}}
    {{if .RemediationNone}}<p><b>Remediation.</b> None required (negative evidence / informational).</p>{{else}}<p><b>Remediation.</b></p><div class="rem">{{.Remediation}}</div>{{end}}
    </div></div>{{end}}
  <h3>Observation Detail</h3><div class="rem">{{.ObservationDetail}}</div></section>` +
	`<section class="page"><h2>5. Attack Narrative</h2><p>{{.AttackNarr}}</p>
  <h3>Attack-path exploration</h3><div class="rem">{{.AttackGraph}}</div>
  <h3>Runtime planner attack-graph</h3><div class="rem">{{.PlannerGraph}}</div>
  <h3>Attack-graph metrics</h3><div class="rem">{{.GraphMetrics}}</div>
  <h3>Adversarial control ledger</h3><div class="rem">{{.AdvLedger}}</div>
  <h3>Human red-team queue</h3><div class="rem">{{.HumanQueue}}</div></section>
  <section class="page"><h2>Edge &amp; Defense Map (CDN / WAF / origin looking-glass)</h2><div class="rem">{{.EdgeMap}}</div></section>` +
	`<section class="page"><h2>6. Compliance Coverage Matrix</h2>
  <p>Findings grouped by control domain — usable as an evidence index for SOC 2 / ISO 27001 / PCI-DSS audits.</p>
  <table class="grid"><thead><tr><th>Control domain</th><th>Findings</th><th>SOC 2</th><th>Owner</th></tr></thead><tbody>
  {{range .Compliance}}<tr><td>{{.Class}}</td><td>{{.N}}</td><td>{{.SOC2}}</td><td>{{.Team}}</td></tr>{{end}}
  </tbody></table></section>` +
	`<section class="page"><h2>Appendix A — Evidence Index</h2>
  {{if .SSNotAvailable}}<p>Screenshots: <b>not available</b> ({{.SSStatusTrim}}).</p>{{else}}<p>Page screenshots ({{.SSStatus}}) are provided in <code>screenshots/</code>, referenced by host. Findings-to-evidence mapping is via the affected-asset field of each finding.</p>{{end}}
  <p>Raw data (subdomains, live services, findings JSON, Shodan OSINT, nuclei output) accompanies this report in <code>data/</code> for team distribution and re-testing (<code>secskills report --retest {{.Target}}</code>). Ticket export: <code>secskills tickets {{.Target}}</code>.</p></section>` +
	`<section class="page"><h2>Appendix B — Tools &amp; Cleanup Log</h2><div class="rem">{{.Appendices}}</div></section>` +
	`<section class="page"><h2>Root-Cause Clustering (shared configuration)</h2><div class="rem">{{.Clustering}}</div></section>` +
	`<section class="page"><h2>Detector Quality Scorecard</h2><div class="rem">{{.Scorecard}}</div></section>` +
	`<section class="page"><h2>Evidence Object Index</h2><div class="rem">{{.EvidenceIndex}}</div></section>` +
	`<section class="page"><h2>Severity Rubric (independent of CVSS)</h2><div class="rem">{{.Rubric}}</div></section>` +
	`<section class="page"><h2>Control Test Ledger</h2><div class="rem">{{.Ledger}}</div></section>` +
	`<section class="page"><h2>Run Attestation</h2><div class="rem">{{.Attestation}}</div></section>`))

// mdBulletsToHTML renders a small markdown excerpt (bullets, pipe tables, inline
// code) to safe HTML. It escapes every input segment, then applies minimal
// formatting — so its output is trusted template.HTML at the call sites.
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
		if strings.HasPrefix(t, "|") {
			cells := strings.Split(strings.Trim(t, "|"), "|")
			if len(cells) > 0 && strings.Contains(cells[0], "---") {
				continue
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

// WriteHTMLReport renders the professional HTML report to output.
func WriteHTMLReport(target, wd, output string) error {
	fs := LoadOrLatest(target, wd)
	if err := enforceReportLint(target, wd, NormalizedForLint(target, wd, fs)); err != nil {
		return err
	}
	report := renderHTMLReport(target, wd, LoadOrLatest(target, wd))
	if output == "" {
		output = target + "_report.html"
	}
	if err := os.WriteFile(output, []byte(report), 0o644); err != nil {
		return err
	}
	fmt.Printf("HTML report: %s\n", output)
	return nil
}

// WritePDFReport renders the HTML report and prints it to PDF with headless Chrome.
func WritePDFReport(target, wd, output string) error {
	if err := enforceReportLint(target, wd, NormalizedForLint(target, wd, LoadOrLatest(target, wd))); err != nil {
		return err
	}
	if output == "" {
		output = target + "_report.pdf"
	}
	htmlPath := output + ".tmp.html"
	if err := os.WriteFile(htmlPath, []byte(renderHTMLReport(target, wd, LoadOrLatest(target, wd))), 0o644); err != nil {
		return err
	}
	defer os.Remove(htmlPath)
	chrome := tooling.ChromePath()
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

// LoadOrLatest returns the workdir findings, falling back to the latest stored run.
func LoadOrLatest(target, wd string) []finding.Finding {
	f := finding.LoadWorkFindings(wd)
	if len(f) > 0 {
		return f
	}
	if b, err := os.ReadFile(filepath.Join(finding.StoreDir(target), "latest")); err == nil {
		var run finding.Run
		if json.Unmarshal(b, &run) == nil {
			return run.Findings
		}
	}
	return nil
}
