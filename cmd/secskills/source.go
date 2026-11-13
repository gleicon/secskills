package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/gleicon/secskills/internal/kb"
)

// cmdSource runs the embedded ast-grep rule set over a path (source mode).
// No network — no authorization gate (FR-7.b). If ast-grep is absent it reports
// the gap and exits without failing the whole run (D-1).
func cmdSource(args []string) error {
	fs2 := flag.NewFlagSet("source", flag.ContinueOnError)
	asJSON := fs2.Bool("json", false, "pass --json through ast-grep")
	if err := fs2.Parse(args); err != nil {
		return err
	}
	target := "."
	if fs2.NArg() > 0 {
		target = fs2.Arg(0)
	}
	if _, err := exec.LookPath("ast-grep"); err != nil {
		fmt.Fprintln(os.Stderr, "[source] ast-grep not installed — install it (see: secskills doctor --tools ast-grep) or review manually.")
		return fmt.Errorf("ast-grep not found")
	}
	rulesDir, cleanup, err := kb.MaterializeRules()
	if err != nil {
		return err
	}
	defer cleanup()

	cfg := filepath.Join(rulesDir, "sgconfig.yml")
	sgArgs := []string{"scan", "--config", cfg, target}
	if *asJSON {
		sgArgs = append(sgArgs, "--json")
	}
	cmd := exec.Command("ast-grep", sgArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// ast-grep exits non-zero when it finds error-level diagnostics — that is a
	// successful scan with findings, not a tool failure. Only surface real
	// execution errors (binary missing already handled above).
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return nil // findings reported to stdout
		}
		return err
	}
	return nil
}
