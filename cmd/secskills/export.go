package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/report"
	"github.com/gleicon/secskills/internal/workspace"
)

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	format := fs.String("format", "sarif", "sarif | cyclonedx")
	output := fs.String("output", "", "write to path (default stdout)")
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills export <target> [--format sarif|cyclonedx] [--output f]")
	}
	target := pos[0]
	findings := report.LoadOrLatest(target, workspace.Workdir(target))
	if len(findings) == 0 {
		return fmt.Errorf("no findings for %s", target)
	}
	for i := range findings {
		finding.EnsureEvidenceFields(&findings[i])
		finding.EnforceSeverityPolicy(&findings[i])
	}
	var doc any
	switch *format {
	case "sarif":
		doc = report.BuildSARIF(target, findings)
	case "cyclonedx", "cdx", "vex":
		doc = report.BuildCycloneDX(target, findings)
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
