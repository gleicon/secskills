package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// cmdTickets exports findings as ticket rows — the finding fields ARE the ticket
// fields (playbook §05), so the report becomes the backlog. CSV (default) or JSON,
// importable into Jira/Linear.
func cmdTickets(args []string) error {
	fs := flag.NewFlagSet("tickets", flag.ContinueOnError)
	format := fs.String("format", "csv", "csv | json")
	output := fs.String("output", "", "write to path (default stdout)")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills tickets <target> [--format csv|json] [--output f]")
	}
	target := pos[0]
	findings := loadOrLatest(target, workdir(target))
	if len(findings) == 0 {
		return fmt.Errorf("no findings for %s", target)
	}
	sortFindings(findings)

	out := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	type ticket struct {
		Key         string   `json:"finding_key"`
		ID          string   `json:"id"`
		Title       string   `json:"title"`
		Severity    string   `json:"severity"`
		SLA         string   `json:"sla"`
		Priority    string   `json:"priority"`
		Asset       string   `json:"affected_asset"`
		OWASP       string   `json:"owasp"`
		CWE         string   `json:"cwe"`
		CVEs        string   `json:"cves"`
		Team        string   `json:"assignee_team"`
		BusinessRisk string  `json:"business_risk"`
		Remediation string   `json:"remediation_ref"`
		Labels      []string `json:"labels"`
	}
	mk := func(i int, f Finding) ticket {
		if f.KBClass == "" {
			classify(&f)
		}
		return ticket{
			Key:          f.Key,
			ID:           fmt.Sprintf("F-%03d", i+1),
			Title:        f.Title,
			Severity:     f.Severity,
			SLA:          slaFor(f.Severity),
			Priority:     priorityFor(f.Severity),
			Asset:        f.Host,
			OWASP:        f.OWASP,
			CWE:          f.CWE,
			CVEs:         strings.Join(f.CVEs, " "),
			Team:         complianceFor(f.KBClass).Team,
			BusinessRisk: businessRisk(f.KBClass, f.Severity),
			Remediation:  "secskills kb " + f.KBClass,
			Labels:       []string{"secskills", f.KBClass, strings.ToLower(f.Severity), "owasp:" + owaspShort(f.OWASP)},
		}
	}

	if *format == "json" {
		var ts []ticket
		for i, f := range findings {
			ts = append(ts, mk(i, f))
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(ts)
	}

	w := csv.NewWriter(out)
	defer w.Flush()
	w.Write([]string{"finding_key", "id", "title", "severity", "sla", "priority", "affected_asset", "owasp", "cwe", "cves", "assignee_team", "business_risk", "remediation_ref", "labels"})
	for i, f := range findings {
		t := mk(i, f)
		w.Write([]string{t.Key, t.ID, t.Title, t.Severity, t.SLA, t.Priority, t.Asset, t.OWASP, t.CWE, t.CVEs, t.Team, t.BusinessRisk, t.Remediation, strings.Join(t.Labels, " ")})
	}
	return nil
}

func priorityFor(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "P1"
	case "HIGH":
		return "P2"
	case "MEDIUM":
		return "P3"
	case "LOW":
		return "P4"
	default:
		return "P5"
	}
}
