package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/gleicon/secskills/internal/tooling"
)

// cmdTLDT wraps the tldt binary for token hygiene and safety preprocessing.
// op: compress | scrub | scan. Input is a file (arg) or stdin. Degrades
// gracefully (passthrough) when tldt is absent, so nothing breaks (D-1).
func cmdTLDT(args []string, op string) error {
	fs2 := flag.NewFlagSet(op, flag.ContinueOnError)
	level := fs2.String("level", "standard", "compress: aggressive|standard|lite")
	label := fs2.String("label", "input", "scan: source label")
	if err := fs2.Parse(args); err != nil {
		return err
	}

	var flags []string
	switch op {
	case "compress":
		flags = []string{"--level", *level, "--sanitize"}
	case "scrub":
		flags = []string{"--sanitize-pii", "--sentences", "1000"}
	case "scan":
		flags = []string{"--detect-injection", "--detect-pii", "--detect-only", "--format", "json"}
		fmt.Fprintf(os.Stderr, "[scan] untrusted source: %s\n", *label)
	default:
		return fmt.Errorf("unknown tldt op %q", op)
	}

	// resolve input: file arg or stdin
	var inFile string
	if fs2.NArg() > 0 {
		inFile = fs2.Arg(0)
	}

	if _, err := exec.LookPath("tldt"); err != nil {
		fmt.Fprintf(os.Stderr, "[tldt] not installed — passthrough (%s). Install: secskills doctor --tools tldt\n", op)
		return tooling.Passthrough(inFile)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cmdArgs []string
	if inFile != "" {
		cmdArgs = append([]string{"-f", inFile}, flags...)
	} else {
		cmdArgs = flags
	}
	cmd := exec.CommandContext(ctx, "tldt", cmdArgs...)
	if inFile == "" {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			fmt.Fprintln(os.Stderr, "[tldt] timed out — passthrough")
			return tooling.Passthrough(inFile)
		}
		return err
	}
	if op == "scan" {
		fmt.Println()
	}
	return nil
}
