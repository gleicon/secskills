package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/tooling"
)

// cmdShodan is a standalone lookup: secskills shodan <domain|ip> [more...]
func cmdShodan(args []string) error {
	fs := flag.NewFlagSet("shodan", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: secskills shodan <domain|ip> [ip...]")
	}
	if !tooling.ShodanReady() {
		return fmt.Errorf("shodan not ready — install CLI and set SHODAN_API_KEY or run `shodan init <key>`")
	}
	for _, t := range fs.Args() {
		sub := "host"
		if strings.Contains(t, ".") && strings.IndexFunc(t, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0 {
			// contains letters -> treat as domain
			if !tooling.IsIPish(t) {
				sub = "domain"
			}
		}
		out, err := tooling.RunCmdTimeout(25*time.Second, "shodan", sub, t)
		if err != nil {
			fmt.Printf("== %s %s: error (%v) ==\n", sub, t, err)
			continue
		}
		fmt.Printf("== shodan %s %s ==\n%s\n", sub, t, out)
	}
	return nil
}
