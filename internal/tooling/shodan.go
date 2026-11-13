package tooling

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ShodanReady reports whether the shodan CLI is installed and a key resolves
// (SHODAN_API_KEY env or ~/.shodan/api_key from `shodan init`).
func ShodanReady() bool {
	if !Has("shodan") {
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

// ShodanEnrich queries Shodan for a domain and its resolved IPs, writing raw
// reference data (software, ports, ASN, org, IPs) to <wd>/shodan/. Best-effort:
// any failure is skipped with a note (D-1). Returns a short summary line.
func ShodanEnrich(wd, domain string, ips []string) string {
	if !ShodanReady() {
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
	out, err := RunCmdTimeout(to, "shodan", args...)
	if err != nil || len(out) == 0 || strings.Contains(string(out), "Error:") {
		return false
	}
	os.WriteFile(filepath.Join(dir, outName), out, 0o644)
	return true
}

// RunCmdTimeout runs a command and kills it after to.
func RunCmdTimeout(to time.Duration, name string, args ...string) ([]byte, error) {
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

// IsIPish reports whether s contains only IPv4/IPv6 address characters.
func IsIPish(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != ':' && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
