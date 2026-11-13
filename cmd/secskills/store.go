package main

import (
	"fmt"

	"github.com/gleicon/secskills/internal/finding"
)

func cmdFindings(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills findings <add|write-run|list|show> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return finding.FindingsAdd(rest)
	case "write-run":
		return finding.FindingsWriteRun(rest)
	case "list":
		return finding.FindingsList(rest)
	case "show":
		return finding.FindingsShow(rest)
	default:
		return fmt.Errorf("unknown findings subcommand %q", sub)
	}
}
