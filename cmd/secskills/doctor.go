package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/tooling"
)

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	mode := fs.String("mode", "all", "source|discover|test|sandbox|live|all")
	cat := fs.String("category", "all", "filter by category")
	tools := fs.String("tools", "", "comma-separated tool names")
	asJSON := fs.Bool("json", false, "machine-readable output")
	quiet := fs.Bool("quiet", false, "only show missing")
	listCat := fs.Bool("list-categories", false, "list categories and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	reg := tooling.ParseRegistry()
	plat := tooling.Platform()

	if *listCat {
		seen := map[string]bool{}
		var cats []string
		for _, t := range reg {
			if !seen[t.Category] {
				seen[t.Category] = true
				cats = append(cats, t.Category)
			}
		}
		sort.Strings(cats)
		fmt.Println("categories:")
		for _, c := range cats {
			fmt.Println("  " + c)
		}
		return nil
	}

	wantTools := map[string]bool{}
	if *tools != "" {
		for _, t := range strings.Split(*tools, ",") {
			wantTools[strings.TrimSpace(t)] = true
		}
	}

	var filtered []tooling.Tool
	missingBaseline := false
	for _, t := range reg {
		if !tooling.ModeMatch(t.Modes, *mode) {
			continue
		}
		if *cat != "all" && *cat != t.Category {
			continue
		}
		if len(wantTools) > 0 && !wantTools[t.Name] {
			continue
		}
		// headless browser: not always on PATH (macOS app bundle) — detect specially
		if t.Name == "chrome" {
			if cp := tooling.ChromePath(); cp != "" {
				t.Status = "present"
				t.Note = "headless browser found: " + cp
			} else {
				t.Status = "absent"
			}
			if plat == "mac" {
				t.Install = tooling.RenderInstall(t.Mac, plat)
			} else {
				t.Install = tooling.RenderInstall(t.Linux, plat)
			}
			filtered = append(filtered, t)
			continue
		}
		if p, err := exec.LookPath(t.Name); err == nil {
			t.Status = "present"
			// build-identity verify: httpx PATH collision (Python vs projectdiscovery)
			if t.Name == "httpx" && !tooling.IsPDHttpx(p) {
				t.Status = "misconfig"
				if pd, ok := tooling.HttpxBin(); ok {
					t.Note = "PATH httpx is NOT projectdiscovery (Python shadow) — use " + pd
				} else {
					t.Note = "PATH httpx is NOT projectdiscovery (Python shadow); install pd httpx"
				}
			}
		} else {
			t.Status = "absent"
		}
		if plat == "mac" {
			t.Install = tooling.RenderInstall(t.Mac, plat)
		} else {
			t.Install = tooling.RenderInstall(t.Linux, plat)
		}
		if t.Status == "absent" && t.Tier == "baseline" {
			missingBaseline = true
		}
		filtered = append(filtered, t)
	}

	if *asJSON {
		b, _ := json.Marshal(filtered)
		fmt.Println(string(b))
		if missingBaseline {
			return fmt.Errorf("baseline tool missing")
		}
		return nil
	}

	fmt.Printf("== secskills doctor ==\nplatform: %s   mode: %s   category: %s\n", plat, *mode, *cat)
	curCat := ""
	for _, t := range filtered {
		if t.Category != curCat {
			fmt.Printf("\n[%s]\n", t.Category)
			curCat = t.Category
		}
		switch t.Status {
		case "present":
			if !*quiet {
				fmt.Printf("  ✓ %-18s %-9s %s\n", t.Name, t.Tier, t.Note)
			}
		case "misconfig":
			fmt.Printf("  ⚠ %-18s %-9s %s\n", t.Name, t.Tier, t.Note)
		default:
			fmt.Printf("  ✗ %-18s %-9s MISSING — %s\n", t.Name, t.Tier, t.Install)
		}
	}
	fmt.Println()
	if missingBaseline {
		fmt.Println("RESULT: baseline tool missing — install the ✗ baseline tools first.")
		return fmt.Errorf("baseline tool missing")
	}
	fmt.Println("RESULT: baseline OK. Install ✗ power tools to widen coverage; tldt recommended.")
	return nil
}
