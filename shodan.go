package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// shodanReady reports whether the shodan CLI is installed and a key resolves
// (SHODAN_API_KEY env or ~/.shodan/api_key from `shodan init`).
func shodanReady() bool {
	if !has("shodan") {
		return false
	}
	if os.Getenv("SHODAN_API_KEY") != "" {
		return true
	}
	home, _ := os.UserHomeDir()
	if _, err := os.Stat(filepath.Join(home, ".shodan", "api_key")); err == nil {
		return true
	}
	// last resort: `shodan info` exits 0 only when a key is configured
	ctx := exec.Command("shodan", "info")
	return ctx.Run() == nil
}

// shodanEnrich queries Shodan for a domain and its resolved IPs, writing raw
// reference data (software, ports, ASN, org, IPs) to <wd>/shodan/. Best-effort:
// any failure is skipped with a note (D-1). Returns a short summary line.
func shodanEnrich(wd, domain string, ips []string) string {
	if !shodanReady() {
		return "[shodan] skipped — CLI absent or no API key (SHODAN_API_KEY / shodan init)"
	}
	dir := filepath.Join(wd, "shodan")
	os.MkdirAll(dir, 0o755)

	// 1. domain view (subdomains + DNS records Shodan knows)
	runShodan(dir, "domain-"+domain+".txt", 25*time.Second, "domain", domain)

	// 2. per-IP host view (ports, software/product+version, ASN, org, CPE, vulns)
	seen := map[string]bool{}
	uniq := []string{}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		uniq = append(uniq, ip)
	}
	if len(uniq) > 15 {
		uniq = uniq[:15] // bound API usage
	}
	got := 0
	for _, ip := range uniq {
		if runShodan(dir, "host-"+ip+".txt", 20*time.Second, "host", ip) {
			got++
		}
	}
	return fmt.Sprintf("[shodan] enriched: domain + %d/%d hosts -> %s", got, len(uniq), dir)
}

func runShodan(dir, outName string, to time.Duration, args ...string) bool {
	out, err := runCmdTimeout(to, "shodan", args...)
	if err != nil || len(out) == 0 || strings.Contains(string(out), "Error:") {
		return false
	}
	os.WriteFile(filepath.Join(dir, outName), out, 0o644)
	return true
}

func runCmdTimeout(to time.Duration, name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
		return out, err
	case <-time.After(to):
		cmd.Process.Kill()
		return nil, fmt.Errorf("timeout")
	}
}

// cmdShodan is a standalone lookup: secskills shodan <domain|ip> [more...]
func cmdShodan(args []string) error {
	fs := flag.NewFlagSet("shodan", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: secskills shodan <domain|ip> [ip...]")
	}
	if !shodanReady() {
		return fmt.Errorf("shodan not ready — install CLI and set SHODAN_API_KEY or run `shodan init <key>`")
	}
	for _, t := range fs.Args() {
		sub := "host"
		if strings.Contains(t, ".") && strings.IndexFunc(t, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0 {
			// contains letters -> treat as domain
			if !isIPish(t) {
				sub = "domain"
			}
		}
		out, err := runCmdTimeout(25*time.Second, "shodan", sub, t)
		if err != nil {
			fmt.Printf("== %s %s: error (%v) ==\n", sub, t, err)
			continue
		}
		fmt.Printf("== shodan %s %s ==\n%s\n", sub, t, out)
	}
	return nil
}

func isIPish(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != ':' && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
