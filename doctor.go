package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// Tool is one row of the embedded registry (tools/registry.tsv).
type Tool struct {
	Name     string `json:"tool"`
	Tier     string `json:"tier"`     // baseline | power | optimizer
	Category string `json:"category"` // core, osint, dns, http, ...
	Modes    string `json:"modes"`    // csv: discover,test,source,...
	Mac      string `json:"-"`
	Linux    string `json:"-"`
	Note     string `json:"note"`
	Status   string `json:"status"`  // present | absent (filled by check)
	Install  string `json:"install"` // platform-resolved command
}

func parseRegistry() []Tool {
	var out []Tool
	for _, line := range strings.Split(strings.TrimSpace(registryTSV), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		out = append(out, Tool{
			Name: f[0], Tier: f[1], Category: f[2], Modes: f[3],
			Mac: f[4], Linux: f[5], Note: f[6],
		})
	}
	return out
}

func platform() string {
	switch runtime.GOOS {
	case "darwin":
		return "mac"
	case "linux":
		return "linux"
	default:
		return "other"
	}
}

// renderInstall turns a registry install spec into a runnable command for the
// current platform, mirroring tools/doctor.sh render_install.
func renderInstall(spec, plat string) string {
	switch {
	case strings.HasPrefix(spec, "go:"):
		return "go install -v " + strings.TrimPrefix(spec, "go:")
	case strings.HasPrefix(spec, "cargo:"):
		return "cargo install " + strings.TrimPrefix(spec, "cargo:") + " --locked"
	case strings.HasPrefix(spec, "pipx:"):
		return "pipx install " + strings.TrimPrefix(spec, "pipx:")
	case strings.HasPrefix(spec, "npm:"):
		return "npm install -g " + strings.TrimPrefix(spec, "npm:")
	case strings.HasPrefix(spec, "cask:"):
		return "brew install --cask " + strings.TrimPrefix(spec, "cask:")
	case strings.HasPrefix(spec, "git:"):
		return "git clone " + strings.TrimPrefix(spec, "git:")
	case spec == "script:trivy":
		return "curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
	case spec == "script:grype":
		return "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
	case spec == "script:syft":
		return "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
	case spec == "script:trufflehog":
		return "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
	default:
		if plat == "mac" {
			return "brew install " + spec
		}
		return "sudo apt-get install -y " + spec
	}
}

func modeMatch(toolModes, req string) bool {
	if req == "all" {
		return true
	}
	m := "," + toolModes + ","
	if strings.Contains(m, ",all,") {
		return true
	}
	if req == "live" {
		return strings.Contains(m, ",discover,") || strings.Contains(m, ",test,") || strings.Contains(m, ",live,")
	}
	return strings.Contains(m, ","+req+",")
}

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
	reg := parseRegistry()
	plat := platform()

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

	var filtered []Tool
	missingBaseline := false
	for _, t := range reg {
		if !modeMatch(t.Modes, *mode) {
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
			if cp := chromePath(); cp != "" {
				t.Status = "present"
				t.Note = "headless browser found: " + cp
			} else {
				t.Status = "absent"
			}
			if plat == "mac" {
				t.Install = renderInstall(t.Mac, plat)
			} else {
				t.Install = renderInstall(t.Linux, plat)
			}
			filtered = append(filtered, t)
			continue
		}
		if p, err := exec.LookPath(t.Name); err == nil {
			t.Status = "present"
			// build-identity verify: httpx PATH collision (Python vs projectdiscovery)
			if t.Name == "httpx" && !isPDHttpx(p) {
				t.Status = "misconfig"
				if pd, ok := httpxBin(); ok {
					t.Note = "PATH httpx is NOT projectdiscovery (Python shadow) — use " + pd
				} else {
					t.Note = "PATH httpx is NOT projectdiscovery (Python shadow); install pd httpx"
				}
			}
		} else {
			t.Status = "absent"
		}
		if plat == "mac" {
			t.Install = renderInstall(t.Mac, plat)
		} else {
			t.Install = renderInstall(t.Linux, plat)
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
