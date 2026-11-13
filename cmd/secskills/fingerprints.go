package main

import (
	"fmt"

	"github.com/gleicon/secskills/internal/engine"
)

// cmdFP manages the technology fingerprint registry.
func cmdFP(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills fp <list|add|import> ...")
	}
	switch args[0] {
	case "list":
		return engine.FPList(args[1:])
	case "add":
		return engine.FPAdd(args[1:])
	case "import":
		return engine.FPImport(args[1:])
	default:
		return fmt.Errorf("unknown fp subcommand %q", args[0])
	}
}
