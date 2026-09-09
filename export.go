package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// M9 — Interoperability exports.
// Emit findings in standard formats so external governance/security systems can
// ingest secskills output without parsing PDFs: SARIF 2.1.0 (code-scanning /
// security dashboards) and CycloneDX 1.5 with embedded VEX (SBOM/vuln pipelines).

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	format := fs.String("format", "sarif", "sarif | cyclonedx")
	output := fs.String("output", "", "write to path (default stdout)")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills export <target> [--format sarif|cyclonedx] [--output f]")
	}
	target := pos[0]
	findings := loadOrLatest(target, workdir(target))
	if len(findings) == 0 {
		return fmt.Errorf("no findings for %s", target)
	}
	for i := range findings {
		ensureEvidenceFields(&findings[i])
		enforceSeverityPolicy(&findings[i])
	}
	var doc any
	switch *format {
	case "sarif":
		doc = buildSARIF(target, findings)
	case "cyclonedx", "cdx", "vex":
		doc = buildCycloneDX(target, findings)
	default:
		return fmt.Errorf("unknown format %q (sarif|cyclonedx)", *format)
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if *output == "" {
		fmt.Println(string(b))
		return nil
	}
	return os.WriteFile(*output, b, 0o644)
}

// --- SARIF 2.1.0 ------------------------------------------------------------

func buildSARIF(target string, fs []Finding) map[string]any {
	// unique rules by detector
	ruleIdx := map[string]int{}
	var rules []map[string]any
	var results []map[string]any
	for i := range fs {
		f := &fs[i]
		det := detectorOf(f)
		if _, ok := ruleIdx[det]; !ok {
			ruleIdx[det] = len(rules)
			rules = append(rules, map[string]any{
				"id":   det,
				"name": det,
				"shortDescription": map[string]string{"text": rootTitle(f)},
				"properties": map[string]any{
					"owasp": f.OWASP, "cwe": f.CWE, "security-severity": cvssNumeric(f),
				},
			})
		}
		results = append(results, map[string]any{
			"ruleId":    det,
			"ruleIndex": ruleIdx[det],
			"level":     sarifLevel(f.Severity),
			"message":   map[string]string{"text": displayTitle(f) + " — " + businessRiskFor(f)},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": f.Host},
				},
			}},
			"partialFingerprints": map[string]string{"secskillsFindingKey": f.Key},
			"properties": map[string]any{
				"severity": f.Severity, "confidence": f.Confidence, "validation": f.Validation,
				"state": f.State, "cvss": cvssString(f), "evidence_refs": f.EvidenceRefs,
			},
		})
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name": "secskills", "version": version, "informationUri": "https://github.com/gleicon/secskills",
				"rules": rules,
			}},
			"results":    results,
			"properties": map[string]any{"target": target},
		}},
	}
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	}
	return "none"
}

func cvssNumeric(f *Finding) string {
	if cvssNotApplicable(f) {
		return "0.0"
	}
	return cvssScoreStr(f)
}

// --- CycloneDX 1.5 + VEX ----------------------------------------------------

func buildCycloneDX(target string, fs []Finding) map[string]any {
	var vulns []map[string]any
	for i := range fs {
		f := &fs[i]
		ratings := []map[string]any{{
			"severity": strings.ToLower(f.Severity), "method": "other", "source": map[string]string{"name": "secskills"},
		}}
		if !cvssNotApplicable(f) {
			vec, score := cvssVector(f)
			ratings = append(ratings, map[string]any{
				"score": score, "severity": strings.ToLower(f.Severity),
				"method": "CVSSv31", "vector": vec, "source": map[string]string{"name": "secskills"},
			})
		}
		id := f.Key
		if len(f.CVEs) > 0 {
			id = f.CVEs[0]
		}
		// VEX analysis state: our validation status maps to the VEX vocabulary.
		vulns = append(vulns, map[string]any{
			"bom-ref":     f.Key,
			"id":          id,
			"ratings":     ratings,
			"description": displayTitle(f),
			"detail":      businessRiskFor(f),
			"affects":     []map[string]any{{"ref": f.Host}},
			"analysis": map[string]any{
				"state":         vexState(f),
				"justification": vexJustification(f),
				"detail":        f.ObservedEvidence,
			},
			"properties": []map[string]string{
				{"name": "secskills:detector", "value": detectorOf(f)},
				{"name": "secskills:confidence", "value": f.Confidence},
				{"name": "secskills:validation", "value": f.Validation},
				{"name": "secskills:owasp", "value": f.OWASP},
			},
		})
	}
	return map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"version":     1,
		"metadata": map[string]any{
			"tools": []map[string]any{{"name": "secskills", "version": version}},
			"component": map[string]any{
				"type": "application", "name": target, "bom-ref": target,
			},
		},
		"vulnerabilities": vulns,
	}
}

// vexState maps our evidence model to the CycloneDX VEX analysis-state vocabulary.
func vexState(f *Finding) string {
	if f.Override != nil && strings.EqualFold(f.Override.ReviewedSev, "INFORMATIONAL") {
		return "false_positive"
	}
	if isInconclusive(f) {
		return "in_triage"
	}
	switch f.Validation {
	case "exploited", "behavior-confirmed":
		return "exploitable"
	case "version-inferred", "config-inferred":
		return "in_triage"
	}
	if strings.EqualFold(f.Severity, "INFORMATIONAL") {
		return "not_affected"
	}
	return "exploitable"
}

func vexJustification(f *Finding) string {
	if strings.EqualFold(f.Severity, "INFORMATIONAL") {
		return "code_not_reachable"
	}
	return ""
}
