package report

import (
	"strings"

	"github.com/gleicon/secskills"
	"github.com/gleicon/secskills/internal/finding"
)

// M9 — Interoperability exports.
// Emit findings in standard formats so external governance/security systems can
// ingest secskills output without parsing PDFs: SARIF 2.1.0 (code-scanning /
// security dashboards) and CycloneDX 1.5 with embedded VEX (SBOM/vuln pipelines).

// --- SARIF 2.1.0 ------------------------------------------------------------

// BuildSARIF renders findings as a SARIF 2.1.0 log, one rule per detector.
func BuildSARIF(target string, fs []finding.Finding) map[string]any {
	// unique rules by detector
	ruleIdx := map[string]int{}
	var rules []map[string]any
	var results []map[string]any
	for i := range fs {
		f := &fs[i]
		det := finding.DetectorOf(f)
		if _, ok := ruleIdx[det]; !ok {
			ruleIdx[det] = len(rules)
			rules = append(rules, map[string]any{
				"id":               det,
				"name":             det,
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
			"message":   map[string]string{"text": finding.DisplayTitle(f) + " — " + finding.BusinessRiskFor(f)},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": f.Host},
				},
			}},
			"partialFingerprints": map[string]string{"secskillsFindingKey": f.Key},
			"properties": map[string]any{
				"severity": f.Severity, "confidence": f.Confidence, "validation": f.Validation,
				"state": f.State, "cvss": finding.CVSSString(f), "evidence_refs": f.EvidenceRefs,
			},
		})
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name": "secskills", "version": secskills.Version, "informationUri": "https://github.com/gleicon/secskills",
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

func cvssNumeric(f *finding.Finding) string {
	if finding.CVSSNotApplicable(f) {
		return "0.0"
	}
	return finding.CVSSScoreStr(f)
}

// --- CycloneDX 1.5 + VEX ----------------------------------------------------

// BuildCycloneDX renders findings as a CycloneDX 1.5 BOM with VEX entries.
func BuildCycloneDX(target string, fs []finding.Finding) map[string]any {
	var vulns []map[string]any
	for i := range fs {
		f := &fs[i]
		ratings := []map[string]any{{
			"severity": strings.ToLower(f.Severity), "method": "other", "source": map[string]string{"name": "secskills"},
		}}
		if !finding.CVSSNotApplicable(f) {
			vec, score := finding.CVSSVector(f)
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
			"description": finding.DisplayTitle(f),
			"detail":      finding.BusinessRiskFor(f),
			"affects":     []map[string]any{{"ref": f.Host}},
			"analysis": map[string]any{
				"state":         vexState(f),
				"justification": vexJustification(f),
				"detail":        f.ObservedEvidence,
			},
			"properties": []map[string]string{
				{"name": "secskills:detector", "value": finding.DetectorOf(f)},
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
			"tools": []map[string]any{{"name": "secskills", "version": secskills.Version}},
			"component": map[string]any{
				"type": "application", "name": target, "bom-ref": target,
			},
		},
		"vulnerabilities": vulns,
	}
}

// vexState maps our evidence model to the CycloneDX VEX analysis-state vocabulary.
func vexState(f *finding.Finding) string {
	if f.Override != nil && strings.EqualFold(f.Override.ReviewedSev, "INFORMATIONAL") {
		return "false_positive"
	}
	if finding.IsInconclusive(f) {
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

func vexJustification(f *finding.Finding) string {
	if strings.EqualFold(f.Severity, "INFORMATIONAL") {
		return "code_not_reachable"
	}
	return ""
}
