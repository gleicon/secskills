package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// runDeep executes the deep-phase tools (nuclei batch, sslscan cipher enumeration,
// screenshots) against the in-scope live URLs. Each tool is optional (D-1): absent
// tools are skipped with a note. Findings are returned for the store.
func runDeep(wd string, urls []string) []Finding {
	var out []Finding
	// 1. nuclei — one batch run over the whole live list (not per host).
	out = append(out, runNucleiBatch(wd, urls)...)
	// 2. sslscan — cipher/protocol enumeration per host, bounded + parallel.
	out = append(out, runSSLScanAll(urls)...)
	// 3. content discovery — ffuf against each host with a small built-in list.
	out = append(out, runContentDiscovery(urls)...)
	// 4. screenshots — visual evidence (httpx -screenshot), best-effort.
	captureScreenshots(wd, urls)
	return out
}

// commonPaths is a small, safe content-discovery list (config/backup/admin exposure).
var commonPaths = []string{
	"/.env", "/.git/HEAD", "/config.json", "/backup.zip", "/.aws/credentials",
	"/admin", "/api-docs", "/swagger.json", "/openapi.json",
	"/phpinfo.php", "/wp-login.php", "/.DS_Store", "/.svn/entries", "/dump.sql",
}

// runContentDiscovery uses ffuf if present, else a bounded native probe, to find
// exposed config/backup/admin paths. Baseline-differential to avoid catch-alls.
func runContentDiscovery(urls []string) []Finding {
	if len(urls) > 25 {
		urls = urls[:25] // bound
	}
	var mu sync.Mutex
	var out []Finding
	runPool(urls, 8, func(u string) {
		base := strings.TrimRight(u, "/")
		c := nonDestructiveClient()
		// baseline random path
		baseCode := 0
		if r, err := c.Get(base + "/secskills-cd-" + randToken()); err == nil {
			baseCode = r.StatusCode
			r.Body.Close()
		}
		for _, p := range commonPaths {
			r, err := c.Get(base + p)
			if err != nil {
				continue
			}
			code := r.StatusCode
			r.Body.Close()
			if code == 200 && baseCode != 200 {
				f := Finding{
					Title:        "Exposed path: " + p,
					Host:         base + p,
					Severity:     "MEDIUM",
					Status:       "open",
					EvidenceCmd:  fmt.Sprintf("curl -sk -o /dev/null -w '%%{http_code}' %s", shellQuote(base+p)),
					ExpectedOpen: "200",
					ProbeKind:    "status", ProbeURL: base + p,
				}
				classify(&f)
				mu.Lock()
				out = append(out, f)
				mu.Unlock()
			}
		}
	})
	fmt.Fprintf(os.Stderr, "[deep] content-discovery: %d exposed paths\n", len(out))
	return out
}

// runNucleiBatch runs nuclei once against a file of URLs and parses JSONL.
func runNucleiBatch(wd string, urls []string) []Finding {
	if !has("nuclei") || len(urls) == 0 {
		if !has("nuclei") {
			fmt.Fprintln(os.Stderr, "[deep] nuclei absent — skipped")
		}
		return nil
	}
	in, err := os.CreateTemp("", "secskills-nuclei-*")
	if err != nil {
		return nil
	}
	in.WriteString(strings.Join(urls, "\n"))
	in.Close()
	defer os.Remove(in.Name())
	outFile := filepath.Join(wd, "nuclei.jsonl")

	// ensure templates exist (first run) — quiet, best-effort, one-time
	uctx, ucancel := context.WithTimeout(context.Background(), 120*time.Second)
	exec.CommandContext(uctx, "nuclei", "-update-templates", "-silent").Run()
	ucancel()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	// broad but bounded: exposure/misconfig/default-login/takeover/cve + common HTTP
	// templates; -duc keeps it non-interactive.
	cmd := exec.CommandContext(ctx, "nuclei", "-l", in.Name(), "-jsonl", "-silent", "-duc",
		"-rate-limit", "150", "-timeout", "8", "-retries", "0",
		"-severity", "low,medium,high,critical",
		"-tags", "exposure,misconfig,default-login,takeover,cve,tech,panel,config",
		"-o", outFile)
	cmd.Run()

	data, _ := os.ReadFile(outFile)
	var fnd []Finding
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var n struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
			MatchedAt string `json:"matched-at"`
		}
		if json.Unmarshal([]byte(line), &n) != nil {
			continue
		}
		sev := strings.ToUpper(n.Info.Severity)
		if sev == "" || sev == "INFO" {
			sev = "LOW"
		}
		f := Finding{
			Title:        "nuclei: " + n.Info.Name + " (" + n.TemplateID + ")",
			Host:         n.MatchedAt,
			Severity:     sev,
			Status:       "open",
			EvidenceCmd:  fmt.Sprintf("nuclei -u %s -id %s -silent | grep -q . && echo HIT", shellQuote(n.MatchedAt), shellQuote(n.TemplateID)),
			ExpectedOpen: "HIT",
			ProbeKind:    "manual",
		}
		classify(&f)
		fnd = append(fnd, f)
	}
	fmt.Fprintf(os.Stderr, "[deep] nuclei: %d findings\n", len(fnd))
	return fnd
}

// runSSLScanAll enumerates TLS ciphers/protocols on each host (A02), bounded + parallel.
func runSSLScanAll(urls []string) []Finding {
	if !has("sslscan") {
		fmt.Fprintln(os.Stderr, "[deep] sslscan absent — skipped (TLS version posture still covered by the base check)")
		return nil
	}
	hosts := map[string]bool{}
	for _, u := range urls {
		if strings.HasPrefix(u, "https://") {
			hosts[hostOf(u)] = true
		}
	}
	list := make([]string, 0, len(hosts))
	for h := range hosts {
		list = append(list, h)
	}
	if len(list) > 40 {
		list = list[:40] // bound
	}
	var mu sync.Mutex
	var out []Finding
	runPool(list, 8, func(h string) {
		if f := sslscanHost(h); f != nil {
			mu.Lock()
			out = append(out, *f)
			mu.Unlock()
		}
	})
	fmt.Fprintf(os.Stderr, "[deep] sslscan: %d hosts with weak TLS\n", len(out))
	return out
}

func sslscanHost(host string) *Finding {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "sslscan", "--no-colour", host+":443").CombinedOutput()
	s := string(out)
	var weakProto, weakCipher []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.Contains(line, "Accepted") {
			continue
		}
		for _, p := range []string{"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"} {
			if strings.Contains(line, p) && !contains(weakProto, p) {
				weakProto = append(weakProto, p)
			}
		}
		up := strings.ToUpper(line)
		for _, c := range []string{"RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "-ANON", "MD5"} {
			if strings.Contains(up, c) && !contains(weakCipher, c) {
				weakCipher = append(weakCipher, c)
			}
		}
	}
	if len(weakProto) == 0 && len(weakCipher) == 0 {
		return nil
	}
	sev := "MEDIUM"
	if contains(weakCipher, "NULL") || contains(weakCipher, "EXPORT") {
		sev = "HIGH"
	}
	parts := []string{}
	if len(weakProto) > 0 {
		parts = append(parts, "protocols: "+strings.Join(weakProto, ","))
	}
	if len(weakCipher) > 0 {
		parts = append(parts, "ciphers: "+strings.Join(weakCipher, ","))
	}
	f := &Finding{
		Title:        "Weak TLS configuration (" + strings.Join(parts, "; ") + ")",
		Host:         "https://" + host,
		Severity:     sev,
		Status:       "open",
		EvidenceCmd:  fmt.Sprintf("sslscan --no-colour %s:443 | grep -E 'Accepted (SSLv|TLSv1.0|TLSv1.1)|RC4|3DES|NULL|EXPORT'", shellQuote(host)),
		ExpectedOpen: "Accepted",
		ProbeKind:    "manual",
	}
	classify(f)
	return f
}

// haveChrome reports whether a headless-capable browser is on PATH.
func haveChrome() bool {
	for _, b := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if _, err := exec.LookPath(b); err == nil {
			return true
		}
	}
	// macOS app bundle
	if _, err := os.Stat("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"); err == nil {
		return true
	}
	return false
}

// captureScreenshots grabs page screenshots via httpx (headless). Requires a
// working headless browser; if unavailable or output is empty, it records
// "not-available" so the report states it rather than shipping 0-byte files.
func captureScreenshots(wd string, urls []string) {
	statusFile := filepath.Join(wd, "screenshots-status.txt")
	mark := func(s string) { os.WriteFile(statusFile, []byte(s), 0o600) }
	bin, ok := httpxBin()
	if !ok || len(urls) == 0 {
		mark("not-available")
		return
	}
	if !haveChrome() {
		fmt.Fprintln(os.Stderr, "[deep] screenshots NOT AVAILABLE — no headless Chrome/Chromium on PATH")
		mark("not-available: no headless browser")
		return
	}
	in, err := os.CreateTemp("", "secskills-ss-*")
	if err != nil {
		mark("not-available")
		return
	}
	in.WriteString(strings.Join(urls, "\n"))
	in.Close()
	defer os.Remove(in.Name())
	ssDir := filepath.Join(wd, "screenshots")
	os.RemoveAll(ssDir)
	os.MkdirAll(ssDir, 0o755)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-l", in.Name(), "-silent",
		"-screenshot", "-srd", ssDir, "-system-chrome", "-timeout", "12", "-threads", "8")
	cmd.Run()

	// keep only non-empty PNGs; delete 0-byte artifacts
	nonEmpty := 0
	filepath.Walk(ssDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".png") {
			return nil
		}
		if info.Size() == 0 {
			os.Remove(p)
		} else {
			nonEmpty++
		}
		return nil
	})
	if nonEmpty == 0 {
		fmt.Fprintln(os.Stderr, "[deep] screenshots NOT AVAILABLE — capture produced only empty files")
		mark("not-available: capture produced empty files")
		return
	}
	mark(fmt.Sprintf("%d captured", nonEmpty))
	fmt.Fprintf(os.Stderr, "[deep] screenshots: %d captured -> %s\n", nonEmpty, ssDir)
}
