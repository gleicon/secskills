package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// gateNotice enforces the authorization gate in the portable core (D-5). The
// binary never sends target traffic without --confirm.
func gateNotice(mode, target string, confirmed bool) error {
	if confirmed {
		return nil
	}
	// A confirmed, unexpired engagement scope file (written by intake) authorizes
	// listed targets without a re-prompt — so a scoped engagement has nothing loose.
	if ok, why := scopeAuthorizes(target); ok {
		fmt.Fprintf(os.Stderr, "[gate] %s\n", why)
		return nil
	}
	fmt.Fprintf(os.Stderr, `AUTHORIZATION REQUIRED — %s mode, target: %s

This sends traffic to / executes against the target. You must have written
authorization from the target owner. Re-run once authorized:

  secskills %s %s --confirm

Non-destructive by default; add --intrusive (+ --intrusive-confirm) for write/credential tests.
`, mode, target, mode, target)
	return fmt.Errorf("authorization not confirmed")
}

func has(tool string) bool { _, err := exec.LookPath(tool); return err == nil }

// rateGate returns a ticker-based limiter honoring SECSKILLS_RATE (default 5/s).
func rateGate() *time.Ticker {
	rps := 5.0
	if v := os.Getenv("SECSKILLS_RATE"); v != "" {
		fmt.Sscanf(v, "%f", &rps)
	}
	if rps <= 0 {
		rps = 1
	}
	return time.NewTicker(time.Duration(float64(time.Second) / rps))
}

// ---- discover ----------------------------------------------------------------

func cmdDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	workers := fs.Int("workers", 20, "resolver/probe concurrency")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills discover <domain> --confirm")
	}
	target := pos[0]
	if err := gateNotice("discover", target, *confirm); err != nil {
		return err
	}
	host := hostOf(target)
	wd := workdir(target)
	writeScope(wd, []string{host})
	fmt.Printf("== discover: %s (workdir %s) ==\n", host, wd)

	// 1. subdomains
	subs := map[string]bool{host: true}
	if has("subfinder") {
		out, _ := exec.Command("subfinder", "-d", host, "-silent", "-all").Output()
		for _, s := range strings.Fields(string(out)) {
			subs[strings.ToLower(s)] = true
		}
		fmt.Printf("[subfinder] %d names\n", len(subs))
	} else {
		fmt.Println("[subfinder] absent — crt.sh (throttled)")
		for _, s := range crtshNames(host) {
			if strings.HasSuffix(s, host) {
				subs[s] = true
			}
		}
		fmt.Printf("[crt.sh] %d names\n", len(subs))
	}
	// confirm scope = target apex + its subdomains only. Reject any name with
	// shell/URL-unsafe characters so a crafted DNS entry can never reach an
	// evidence command or the shell.
	var subList []string
	for s := range subs {
		if (s == host || strings.HasSuffix(s, "."+host)) && validHost(s) {
			subList = append(subList, s)
		}
	}
	writeArtifactLines(wd, "subs.txt", subList)
	writeScope(wd, subList)

	// 2. resolve — dnsx (fast/concurrent) or net.LookupHost fallback
	resolved := dnsxResolve(subList, *workers)
	writeArtifactLines(wd, "resolved.txt", resolved)
	fmt.Printf("[resolve] %d/%d resolvable\n", len(resolved), len(subList))

	// 3. live-host probe — pd httpx (temp-file, minimal flags) or Go fallback
	lives := httpxProbe(resolved, *workers)
	// keep only in-scope
	var inScope []LiveHost
	for _, l := range lives {
		if scopeCheck(wd, l.URL) {
			inScope = append(inScope, l)
		}
	}
	b, _ := json.MarshalIndent(inScope, "", "  ")
	os.WriteFile(filepath.Join(wd, "live_hosts.json"), b, 0o644)

	fmt.Printf("[probe] %d live services -> %s/live_hosts.json\n", len(inScope), wd)
	for _, l := range inScope {
		flag := ""
		hay := strings.ToLower(l.URL + " " + l.Server + " " + l.Title)
		for _, t := range []string{"keycloak", "grafana", "prometheus", "harbor", "vault", "argocd", "kibana", "jenkins", "gitlab", "registry", "console"} {
			if strings.Contains(hay, t) {
				flag = "  <== " + t
			}
		}
		fmt.Printf("  %-4d %-45s %-20s%s\n", l.Status, l.URL, l.Server, flag)
	}
	// 4. Shodan enrichment (software/ports/ASN/org) when CLI + key present.
	var ips []string
	ipseen := map[string]bool{}
	for _, name := range resolved {
		if addrs, err := net.LookupHost(name); err == nil {
			for _, a := range addrs {
				if !ipseen[a] {
					ipseen[a] = true
					ips = append(ips, a)
				}
			}
		}
	}
	writeArtifactLines(wd, "ips.txt", ips)
	fmt.Println(shodanEnrich(wd, host, ips))

	fmt.Printf("\nNext: secskills test %s --confirm\n", host)
	return nil
}

// dnsResolvable reports whether a hostname resolves.
func dnsResolvable(h string) bool { _, err := net.LookupHost(h); return err == nil }

// goProbe is the native fallback when pd httpx is unavailable: rate-limited Go
// HTTP probe (https then http) of each host.
func goProbe(hosts []string, workers int) []LiveHost {
	tick := rateGate()
	defer tick.Stop()
	var mu sync.Mutex
	var out []LiveHost
	runPool(hosts, workers, func(name string) {
		for _, scheme := range []string{"https://", "http://"} {
			<-tick.C
			u := scheme + name
			c := nonDestructiveClient()
			req, _ := http.NewRequest("GET", u, nil)
			req.Header.Set("User-Agent", userAgent)
			resp, err := c.Do(req)
			if err != nil {
				continue
			}
			srv := resp.Header.Get("Server")
			resp.Body.Close()
			mu.Lock()
			out = append(out, LiveHost{URL: u, Status: resp.StatusCode, Server: safeField(srv)})
			mu.Unlock()
			return
		}
	})
	return out
}

// ---- test --------------------------------------------------------------------

// runAdversarialStage is the adversarial-readonly module list for one host.
// It lives outside the test closure so per-host orchestration stays scannable as
// modules are added. Modules that issue their own request sequence (the LLM
// probes) take the rate gate and charge one tick per request; single-pass
// modules take one tick here.
func runAdversarialStage(wd, u string, lh LiveHost, oast *OAST, tick *time.Ticker) []Finding {
	var fnd []Finding
	<-tick.C
	fnd = append(fnd, runAdversarial(wd, u, oast)...)
	if f := llmWarmupProbe(wd, u, tick.C); f != nil {
		fnd = append(fnd, *f)
	}
	fnd = append(fnd, llmChatbotProbe(wd, u, oast, tick.C)...)
	if lh.Status == 401 || lh.Status == 403 {
		<-tick.C
		if f := bypassProbe(wd, u, lh.Status); f != nil {
			fnd = append(fnd, *f)
		}
		<-tick.C
		if f := trustedHeaderBypass(wd, u, lh.Status); f != nil {
			fnd = append(fnd, *f)
		}
	}
	return fnd
}

func cmdTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	intrusive := fs.Bool("intrusive", false, "enable write/credential tests")
	intrusiveOK := fs.Bool("intrusive-confirm", false, "second confirmation for intrusive tests")
	deep := fs.Bool("deep", false, "deep phase: nuclei + sslscan + content-discovery + screenshots (slow)")
	profileFlag := fs.String("profile", "safe-active", "aggression profile: passive | safe-active | adversarial-readonly | authorized-exploit")
	authToken := fs.String("auth-token", "", "Bearer token for authenticated testing (optional)")
	authTokenB := fs.String("auth-token-b", "", "second identity Bearer token for BOLA/authz differential (optional)")
	cookieB := fs.String("cookie-b", "", "second identity Cookie header for BOLA/authz differential (optional)")
	cookie := fs.String("cookie", "", "Cookie header for authenticated testing (optional)")
	authHeader := fs.String("auth-header", "", "raw 'Name: value' header for authenticated testing (optional)")
	save := fs.Bool("save", true, "persist a run file after testing")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills test <target> --confirm [--intrusive --intrusive-confirm]")
	}
	target := pos[0]
	if err := gateNotice("test", target, *confirm); err != nil {
		return err
	}
	if *intrusive && !*intrusiveOK {
		return fmt.Errorf("--intrusive requires a second confirmation: add --intrusive-confirm")
	}
	wd := workdir(target)
	started := nowRFC()
	prof := parseProfile(*profileFlag)
	if *intrusive && prof < ProfileAuthorizedExploit {
		prof = ProfileAuthorizedExploit
	}
	os.WriteFile(filepath.Join(wd, "profile.txt"), []byte(prof.String()), 0o644)
	oast := newOAST()
	advReset()
	if !fileExists(filepath.Join(wd, "scope.txt")) {
		writeScope(wd, []string{hostOf(target)})
	}

	// Credential-gated authenticated testing: run only if creds are supplied;
	// otherwise record "not available" so the report states it explicitly.
	authHeaders := map[string]string{}
	if *authToken != "" {
		authHeaders["Authorization"] = "Bearer " + *authToken
	}
	if *cookie != "" {
		authHeaders["Cookie"] = *cookie
	}
	if *authHeader != "" {
		if k, v, ok := strings.Cut(*authHeader, ":"); ok {
			authHeaders[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	authProvided := len(authHeaders) > 0
	if authProvided {
		os.WriteFile(filepath.Join(wd, "auth-status.txt"), []byte("provided"), 0o600)
	} else {
		os.WriteFile(filepath.Join(wd, "auth-status.txt"), []byte("not-available"), 0o600)
	}

	// targets: live hosts from a prior discover, else the target itself
	hosts := liveHosts(wd)
	if len(hosts) == 0 {
		hosts = []LiveHost{{URL: normalizeURL(target)}}
	}
	fmt.Printf("== test: %d target(s) [%s] ==\n", len(hosts), modeLabel(*intrusive))

	tick := rateGate()
	defer tick.Stop()
	// parallelize per-host checks; the shared ticker still bounds global request
	// rate, so concurrency speeds wall-clock without exceeding the rate limit.
	var mu sync.Mutex
	seq := 0
	var inScopeURLs []string
	names := make([]string, 0, len(hosts))
	byURL := map[string]LiveHost{}
	for _, lh := range hosts {
		names = append(names, lh.URL)
		byURL[lh.URL] = lh
	}
	workers := 12
	runPool(names, workers, func(u string) {
		if !scopeCheck(wd, u) {
			return
		}
		lh := byURL[u]
		var fnd []Finding
		<-tick.C
		fnd = append(fnd, checkSecurityHeaders(u)...)
		<-tick.C
		fnd = append(fnd, checkTLS(u)...)
		<-tick.C
		fnd = append(fnd, checkExposure(u)...)
		<-tick.C
		fnd = append(fnd, runDetectorPacks(wd, u)...)
		// LLM canary reflection (AC-2): one benign POST, safe for every profile,
		// SSRF-guarded; it charges its own rate-gate tick per request.
		if f := llmCanaryProbe(wd, u, tick.C); f != nil {
			fnd = append(fnd, *f)
		}
		<-tick.C
		if f := corsDifferential(wd, u); f != nil {
			fnd = append(fnd, *f)
		}
		if prof.adversarial() {
			fnd = append(fnd, runAdversarialStage(wd, u, lh, oast, tick)...)
		}
		if c := cveLookup(u, lh.Server); c != nil {
			fnd = append(fnd, *c)
		}
		// runtime capability planner: discovered capabilities trigger follow-up
		// probes and persisted attack-graph edges (adversarial profile).
		if prof.adversarial() {
			fnd = append(fnd, runPlanner(wd, hostOf(u), fnd)...)
		}
		// persist incrementally + thread-safe so a run killed by a time cap keeps
		// its partial findings (no write-at-end data loss).
		mu.Lock()
		inScopeURLs = append(inScopeURLs, u)
		for i := range fnd {
			seq++
			fnd[i].ID = fmt.Sprintf("F%03d", seq)
			classify(&fnd[i])
			addFinding(wd, fnd[i])
		}
		mu.Unlock()
		fmt.Printf("  %-45s %d findings\n", u, len(fnd))
	})

	// authenticated pass (only when credentials supplied)
	if authProvided {
		fmt.Printf("== authenticated testing (credentials supplied) ==\n")
		// second identity for BOLA/authz differential (authorized-exploit depth)
		credB := map[string]string{}
		if *authTokenB != "" {
			credB["Authorization"] = "Bearer " + *authTokenB
		}
		if *cookieB != "" {
			credB["Cookie"] = *cookieB
		}
		record := func(f Finding) {
			mu.Lock()
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			classify(&f)
			addFinding(wd, f)
			mu.Unlock()
		}
		// JWT inspection of the supplied bearer token (once)
		for _, f := range jwtInspect(*authToken) {
			record(f)
		}
		for _, u := range inScopeURLs {
			for _, f := range checkAuthenticated(u, authHeaders) {
				record(f)
			}
			if len(credB) > 0 {
				if f := authzDifferential(wd, u, authHeaders, credB); f != nil {
					record(*f)
				}
			}
		}
	} else {
		fmt.Println("== authenticated testing: NOT AVAILABLE (no credentials provided) ==")
	}

	// deep phase (--deep): batch nuclei + sslscan cipher enum + screenshots
	if *deep {
		fmt.Printf("== deep phase: nuclei + sslscan + screenshots (%d hosts) ==\n", len(inScopeURLs))
		for _, f := range runDeep(wd, inScopeURLs) {
			mu.Lock()
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			classify(&f)
			addFinding(wd, f)
			mu.Unlock()
		}
	}
	total := seq

	// prompt-injection defense: scan collected artifacts (target output) for
	// content engineered to hijack the reading LLM; emit a finding if detected.
	for _, art := range []struct{ path, label string }{
		{filepath.Join(wd, "live_hosts.json"), "live-host titles/headers"},
		{filepath.Join(wd, "nuclei.jsonl"), "nuclei output"},
		{filepath.Join(wd, "subs.txt"), "subdomain names"},
	} {
		if f := scanArtifactForInjection(art.path, art.label); f != nil {
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			addFinding(wd, *f)
			fmt.Printf("  [prompt-injection] flagged in %s — recorded as finding\n", art.label)
		}
	}

	// DNS hygiene + object-storage enumeration + edge recon run once per apex.
	if apex := registrableDomain(hostOf(target)); apex != "" {
		apexFindings := dnsHygiene(apex)
		if prof.adversarial() {
			apexFindings = append(apexFindings, enumObjectStorage(wd, apex, names)...)
			if _, edgeFindings := runEdgeRecon(wd, target, prof); len(edgeFindings) > 0 {
				apexFindings = append(apexFindings, edgeFindings...)
			}
		}
		for _, f := range apexFindings {
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			classify(&f)
			addFinding(wd, f)
		}
	}
	writeAdvStats(wd)
	writeRunMeta(wd, target, started, loadWorkFindings(wd), *deep, *intrusive)
	if _, err := signRunManifest(wd); err == nil {
		fmt.Println("run attestation signed (ed25519): run-attestation.sig")
	}
	if _, err := signEvidenceChain(wd); err == nil {
		fmt.Println("evidence chain signed (ed25519): evidence-chain.sig")
	}
	fmt.Printf("\n%d findings -> %s\n", total, workFindings(wd))
	fmt.Println("Remediation per finding: secskills kb <class>. Report: secskills report --render", target)
	if *save {
		if path, err := writeRun(target, wd, "full"); err == nil {
			fmt.Printf("run saved: %s\n", path)
		}
	}
	return nil
}

func runNuclei(url string) []Finding {
	out, _ := exec.Command("nuclei", "-u", url, "-jsonl", "-silent",
		"-rate-limit", "50", "-timeout", "10",
		"-severity", "low,medium,high,critical",
		"-tags", "exposure,misconfig,default-login,takeover").Output()
	var fnd []Finding
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
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
		fnd = append(fnd, Finding{
			ID:           fmt.Sprintf("NUC-%02d", i+1),
			Title:        "nuclei: " + n.Info.Name + " (" + n.TemplateID + ")",
			Host:         n.MatchedAt,
			Severity:     strings.ToUpper(n.Info.Severity),
			Status:       "open",
			EvidenceCmd:  fmt.Sprintf("nuclei -u %q -id %q -silent | grep -q . && echo HIT", url, n.TemplateID),
			ExpectedOpen: "HIT",
		})
	}
	return fnd
}

// ---- sandbox -----------------------------------------------------------------

func cmdSandbox(args []string) error {
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	port := fs.Int("port", 8080, "port the containerized app listens on")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills sandbox <build-context> --confirm [--port N]")
	}
	if !has("docker") {
		return fmt.Errorf("sandbox mode requires Docker (not installed) — refusing, never fakes isolation. Install: secskills doctor --tools docker")
	}
	ctx := pos[0]
	if err := gateNotice("sandbox", ctx, *confirm); err != nil {
		return err
	}
	tag := fmt.Sprintf("secskills-target:%d", time.Now().Unix())
	fmt.Printf("== sandbox: build %s ==\n", ctx)
	if out, err := exec.Command("docker", "build", "-t", tag, ctx).CombinedOutput(); err != nil {
		return fmt.Errorf("docker build failed: %v\n%s", err, out)
	}
	// isolated run: no host mounts, dropped caps, published only to loopback
	pub := fmt.Sprintf("127.0.0.1::%d", *port)
	runOut, err := exec.Command("docker", "run", "-d", "--rm",
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"-p", pub, tag).Output()
	if err != nil {
		exec.Command("docker", "rmi", "-f", tag).Run()
		return fmt.Errorf("docker run failed: %v", err)
	}
	cid := strings.TrimSpace(string(runOut))
	teardown := func() {
		exec.Command("docker", "stop", cid).Run()
		exec.Command("docker", "rmi", "-f", tag).Run()
	}
	defer teardown()

	mapped, _ := exec.Command("docker", "port", cid, fmt.Sprint(*port)).Output()
	addr := strings.TrimSpace(string(mapped))
	if i := strings.LastIndex(addr, "\n"); i >= 0 {
		addr = addr[i+1:]
	}
	if addr == "" {
		return fmt.Errorf("could not resolve published port for container")
	}
	url := "http://" + addr
	fmt.Printf("== sandbox: running (cap-drop=ALL, no mounts) at %s ==\n", url)
	time.Sleep(2 * time.Second) // let the app boot

	wd := workdir("sandbox-" + tag)
	writeScope(wd, []string{hostOf(url)})
	var fnd []Finding
	fnd = append(fnd, checkSecurityHeaders(url)...)
	fnd = append(fnd, checkExposure(url)...)
	for i := range fnd {
		fnd[i].ID = fmt.Sprintf("SBX-%02d", i+1)
		addFinding(wd, fnd[i])
	}
	fmt.Printf("[sandbox] %d findings against isolated instance -> %s\n", len(fnd), workFindings(wd))
	return nil
}

// ---- helpers -----------------------------------------------------------------

func modeLabel(intrusive bool) string {
	if intrusive {
		return "INTRUSIVE"
	}
	return "non-destructive"
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func normalizeURL(t string) string {
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return t
	}
	return "https://" + t
}

func liveHosts(wd string) []LiveHost {
	b, err := os.ReadFile(filepath.Join(wd, "live_hosts.json"))
	if err != nil {
		return nil
	}
	var lives []LiveHost
	json.Unmarshal(b, &lives)
	return lives
}

func writeArtifactLines(wd, name string, lines []string) {
	os.WriteFile(filepath.Join(wd, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// concurrentFilter keeps items for which keep() is true, bounded concurrency.
func concurrentFilter(items []string, workers int, keep func(string) bool) []string {
	in := make(chan string)
	var mu sync.Mutex
	var out []string
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range in {
				if keep(it) {
					mu.Lock()
					out = append(out, it)
					mu.Unlock()
				}
			}
		}()
	}
	for _, it := range items {
		in <- it
	}
	close(in)
	wg.Wait()
	return out
}

// runPool runs fn over items with bounded concurrency.
func runPool(items []string, workers int, fn func(string)) {
	in := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range in {
				fn(it)
			}
		}()
	}
	for _, it := range items {
		in <- it
	}
	close(in)
	wg.Wait()
}
