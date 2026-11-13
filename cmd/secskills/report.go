package main

import (
	"flag"
	"fmt"
	"strings"

	reportpkg "github.com/gleicon/secskills/internal/report"
	"github.com/gleicon/secskills/internal/workspace"
)

// cmdReport handles --retest (re-probe latest run) for now; full render is
// documented in lib/report-template.md and produced by the model from findings.
func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	retest := fs.String("retest", "", "target to re-probe against its latest run")
	render := fs.String("render", "", "target: render a markdown report from its findings")
	htmlT := fs.String("html", "", "target: render a professional HTML report")
	pdfT := fs.String("pdf", "", "target: render a professional PDF report (needs headless Chrome)")
	auditT := fs.String("audit", "", "target: render a concise auditor evidence report (control objectives + ledger + attestation)")
	lintT := fs.String("lint", "", "target: run the report-generation linter (invariants) and report violations")
	output := fs.String("output", "", "write rendered report to this path (default stdout/auto)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *retest != "":
		return reportpkg.DoRetest(*retest)
	case *render != "":
		return reportpkg.DoRender(*render, *output)
	case *htmlT != "":
		return reportpkg.WriteHTMLReport(*htmlT, workspace.Workdir(*htmlT), *output)
	case *pdfT != "":
		return reportpkg.WritePDFReport(*pdfT, workspace.Workdir(*pdfT), *output)
	case *auditT != "":
		return reportpkg.DoAudit(*auditT, *output)
	case *lintT != "":
		wd := workspace.Workdir(*lintT)
		vs := reportpkg.ReportLint(*lintT, wd, reportpkg.NormalizedForLint(*lintT, wd, reportpkg.LoadOrLatest(*lintT, wd)))
		if len(vs) == 0 {
			fmt.Println("report lint: clean")
			return nil
		}
		return fmt.Errorf("report lint: %d violation(s):\n  - %s", len(vs), strings.Join(vs, "\n  - "))
	default:
		return fmt.Errorf("usage: secskills report --render|--html|--pdf|--audit <target> [--output f] | --retest <target>")
	}
}
