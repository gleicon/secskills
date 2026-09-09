package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// httpxBin resolves the projectdiscovery httpx binary, working around the common
// PATH collision where Python's httpx shadows it. Returns ("",false) if no pd
// build is found.
func httpxBin() (string, bool) {
	// 1. PATH httpx, if it is the pd build
	if p, err := exec.LookPath("httpx"); err == nil && isPDHttpx(p) {
		return p, true
	}
	// 2. Homebrew Cellar and common install dirs
	candidates := []string{}
	if out, err := exec.Command("brew", "--prefix").Output(); err == nil {
		base := strings.TrimSpace(string(out))
		matches, _ := filepath.Glob(base + "/Cellar/httpx/*/bin/httpx")
		candidates = append(candidates, matches...)
	}
	if gp := goPathBin(); gp != "" {
		candidates = append(candidates, filepath.Join(gp, "httpx"))
	}
	for _, c := range candidates {
		if isPDHttpx(c) {
			return c, true
		}
	}
	return "", false
}

// isPDHttpx reports whether the binary at path is projectdiscovery httpx.
func isPDHttpx(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	return strings.Contains(strings.ToLower(string(out)), "projectdiscovery") ||
		strings.Contains(strings.ToLower(string(out)), "current version")
}

func goPathBin() string {
	if out, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		return filepath.Join(strings.TrimSpace(string(out)), "bin")
	}
	return ""
}

// dnsxResolve resolves a host list with dnsx (fast, concurrent) if present,
// else falls back to concurrent net.LookupHost. Returns resolvable hosts.
func dnsxResolve(hosts []string, workers int) []string {
	if p, err := exec.LookPath("dnsx"); err == nil {
		tmp, err := os.CreateTemp("", "secskills-dnsx-in-*")
		if err == nil {
			tmp.WriteString(strings.Join(hosts, "\n"))
			tmp.Close()
			defer os.Remove(tmp.Name())
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			out, _ := exec.CommandContext(ctx, p, "-l", tmp.Name(), "-silent", "-t", "100").Output()
			var res []string
			for _, l := range strings.Fields(string(out)) {
				res = append(res, strings.ToLower(l))
			}
			if len(res) > 0 {
				return res
			}
		}
	}
	// fallback: concurrent net.LookupHost (from mode.go concurrentFilter)
	return concurrentFilter(hosts, workers, func(h string) bool { return dnsResolvable(h) })
}

// LiveHost is a probed service.
type LiveHost struct {
	URL    string `json:"url"`
	Status int    `json:"status_code"`
	Title  string `json:"title"`
	Server string `json:"webserver"`
}

// httpxProbe probes resolved hosts with pd httpx, minimal fast flags, writing to
// a temp file (avoids the non-TTY stdout buffering trap) and reading it back.
// Runs to completion under a generous context timeout. Falls back to the native
// Go probe if pd httpx is unavailable.
func httpxProbe(hosts []string, workers int) []LiveHost {
	bin, ok := httpxBin()
	if !ok {
		return goProbe(hosts, workers)
	}
	in, err := os.CreateTemp("", "secskills-httpx-in-*")
	if err != nil {
		return goProbe(hosts, workers)
	}
	in.WriteString(strings.Join(hosts, "\n"))
	in.Close()
	defer os.Remove(in.Name())
	outFile := in.Name() + ".jsonl"
	defer os.Remove(outFile)

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	// minimal fast flags only — no -tls-grab/-tech-detect/-cdn (they hang)
	cmd := exec.CommandContext(ctx, bin, "-l", in.Name(),
		"-silent", "-json", "-sc", "-title", "-server", "-location",
		"-threads", itoa(workers), "-timeout", "6", "-retries", "0",
		"-no-color", "-o", outFile)
	cmd.Run()

	data, _ := os.ReadFile(outFile)
	var lives []LiveHost
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var lh LiveHost
		if json.Unmarshal([]byte(line), &lh) == nil && lh.URL != "" {
			lh.Title = safeField(lh.Title) // untrusted target data
			lh.Server = safeField(lh.Server)
			lives = append(lives, lh)
		}
	}
	return lives
}

func itoa(n int) string {
	if n <= 0 {
		return "40"
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
