package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/report"
	"github.com/gleicon/secskills/internal/workspace"
)

// cmdTickets exports findings as ticket rows — the finding fields ARE the ticket
// fields (playbook §05), so the report becomes the backlog. CSV (default) or JSON,
// importable into Jira/Linear.
func cmdTickets(args []string) error {
	fs := flag.NewFlagSet("tickets", flag.ContinueOnError)
	format := fs.String("format", "csv", "csv | json")
	output := fs.String("output", "", "write to path (default stdout)")
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills tickets <target> [--format csv|json] [--output f]")
	}
	target := pos[0]
	wd, err := workspace.Workdir(target)
	if err != nil {
		return err
	}
	findings := report.LoadOrLatest(target, wd)
	if len(findings) == 0 {
		return fmt.Errorf("no findings for %s", target)
	}
	findings = report.DedupeByKey(findings)
	finding.SortFindings(findings)

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
		Key          string   `json:"finding_key"`
		ID           string   `json:"id"`
		Title        string   `json:"title"`
		Severity     string   `json:"severity"`
		SLA          string   `json:"sla"`
		Priority     string   `json:"priority"`
		Asset        string   `json:"affected_asset"`
		OWASP        string   `json:"owasp"`
		CWE          string   `json:"cwe"`
		CVEs         string   `json:"cves"`
		Team         string   `json:"assignee_team"`
		BusinessRisk string   `json:"business_risk"`
		Remediation  string   `json:"remediation_ref"`
		Labels       []string `json:"labels"`
	}
	mk := func(i int, f finding.Finding) ticket {
		if f.KBClass == "" {
			finding.Classify(&f)
		}
		return ticket{
			Key:          f.Key,
			ID:           fmt.Sprintf("F-%03d", i+1),
			Title:        f.Title,
			Severity:     f.Severity,
			SLA:          finding.SLAFor(f.Severity),
			Priority:     report.PriorityFor(f.Severity),
			Asset:        f.Host,
			OWASP:        f.OWASP,
			CWE:          f.CWE,
			CVEs:         strings.Join(f.CVEs, " "),
			Team:         finding.ComplianceFor(f.KBClass).Team,
			BusinessRisk: finding.BusinessRisk(f.KBClass, f.Severity),
			Remediation:  "secskills kb " + f.KBClass,
			Labels:       []string{"secskills", f.KBClass, strings.ToLower(f.Severity), "owasp:" + report.OwaspShort(f.OWASP)},
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
