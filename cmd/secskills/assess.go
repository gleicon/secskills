package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/report"
	"github.com/gleicon/secskills/internal/scope"
	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
	"github.com/gleicon/secskills/internal/workspace"
)

func cmdDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	workers := fs.Int("workers", 20, "resolver/probe concurrency")
	asn := fs.String("asn", "", "discover by ASN (e.g. AS64500): announced prefixes -> IP inventory")
	cidr := fs.String("cidr", "", "discover by CIDR (e.g. 203.0.113.0/24): IP inventory")
	allowLarge := fs.Bool("allow-large", false, "permit a block wider than /20 (deliberate, logged)")
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if *asn != "" || *cidr != "" {
		return exposure.DiscoverBlock(*asn, *cidr, *allowLarge, *confirm, *workers)
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills discover <domain> --confirm  |  discover --asn AS64500 --confirm  |  discover --cidr 203.0.113.0/24 --confirm")
	}
	target := pos[0]
	if err := scope.GateNotice("discover", target, *confirm); err != nil {
		return err
	}
	host := netsec.HostOf(target)
	wd, err := workspace.Workdir(target)
	if err != nil {
		return err
	}
	workspace.WriteScope(wd, []string{host})
	fmt.Printf("== discover: %s (workdir %s) ==\n", host, wd)

	// 1. subdomains
	subs := map[string]bool{host: true}
	if tooling.Has("subfinder") {
		out, _ := exec.Command("subfinder", "-d", host, "-silent", "-all").Output()
		for _, s := range strings.Fields(string(out)) {
			subs[strings.ToLower(s)] = true
		}
		fmt.Printf("[subfinder] %d names\n", len(subs))
	} else {
		fmt.Println("[subfinder] absent — crt.sh (throttled)")
		for _, s := range fetch.CrtshNames(host) {
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
		if (s == host || strings.HasSuffix(s, "."+host)) && netsec.ValidHost(s) {
			subList = append(subList, s)
		}
	}
	engine.WriteArtifactLines(wd, "subs.txt", subList)
	workspace.WriteScope(wd, subList)

	// 2. resolve — dnsx (fast/concurrent) or net.LookupHost fallback
	resolved := tooling.DnsxResolve(subList, *workers)
	engine.WriteArtifactLines(wd, "resolved.txt", resolved)
	fmt.Printf("[resolve] %d/%d resolvable\n", len(resolved), len(subList))

	// 3. live-host probe — pd httpx (temp-file, minimal flags) or Go fallback
	lives := tooling.HttpxProbe(resolved, *workers)
	// keep only in-scope
	var inScope []tooling.LiveHost
	for _, l := range lives {
		if workspace.ScopeCheck(wd, l.URL) {
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
	engine.WriteArtifactLines(wd, "ips.txt", ips)
	fmt.Println(tooling.ShodanEnrich(wd, host, ips))

	fmt.Printf("\nNext: secskills test %s --confirm\n", host)
	return nil
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
	insecureAuth := fs.Bool("insecure-auth", false, "skip TLS verification for credentialed requests (self-signed targets only; exposes credentials to a MITM)")
	authHeader := fs.String("auth-header", "", "raw 'Name: value' header for authenticated testing (optional)")
	save := fs.Bool("save", true, "persist a run file after testing")
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills test <target> --confirm [--intrusive --intrusive-confirm]")
	}
	target := pos[0]
	if err := scope.GateNotice("test", target, *confirm); err != nil {
		return err
	}
	if *intrusive && !*intrusiveOK {
		return fmt.Errorf("--intrusive requires a second confirmation: add --intrusive-confirm")
	}
	wd, err := workspace.Workdir(target)
	if err != nil {
		return err
	}
	started := finding.NowRFC()
	prof := finding.ParseProfile(*profileFlag)
	if *intrusive && prof < finding.ProfileAuthorizedExploit {
		prof = finding.ProfileAuthorizedExploit
	}
	os.WriteFile(filepath.Join(wd, "profile.txt"), []byte(prof.String()), 0o644)
	oast := engine.NewOAST()
	engine.AdvReset()
	if !textutil.FileExists(filepath.Join(wd, "scope.txt")) {
		workspace.WriteScope(wd, []string{netsec.HostOf(target)})
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
	fetch.InsecureAuth = *insecureAuth
	if authProvided {
		os.WriteFile(filepath.Join(wd, "auth-status.txt"), []byte("provided"), 0o600)
	} else {
		os.WriteFile(filepath.Join(wd, "auth-status.txt"), []byte("not-available"), 0o600)
	}

	// targets: live hosts from a prior discover, else the target itself
	hosts := tooling.LiveHosts(wd)
	if len(hosts) == 0 {
		hosts = []tooling.LiveHost{{URL: engine.NormalizeURL(target)}}
	}
	fmt.Printf("== test: %d target(s) [%s] ==\n", len(hosts), engine.ModeLabel(*intrusive))

	tick := fetch.RateGate()
	defer tick.Stop()
	// parallelize per-host checks; the shared ticker still bounds global request
	// rate, so concurrency speeds wall-clock without exceeding the rate limit.
	var mu sync.Mutex
	seq := 0
	var inScopeURLs []string
	names := make([]string, 0, len(hosts))
	byURL := map[string]tooling.LiveHost{}
	for _, lh := range hosts {
		names = append(names, lh.URL)
		byURL[lh.URL] = lh
	}
	workers := 12
	tooling.RunPool(names, workers, func(u string) {
		if !workspace.ScopeCheck(wd, u) {
			return
		}
		lh := byURL[u]
		var fnd []finding.Finding
		<-tick.C
		fnd = append(fnd, engine.CheckSecurityHeaders(u)...)
		<-tick.C
		fnd = append(fnd, engine.CheckTLS(u)...)
		<-tick.C
		fnd = append(fnd, engine.CheckExposure(u)...)
		<-tick.C
		fnd = append(fnd, engine.RunDetectorPacks(wd, u)...)
		// LLM canary reflection (AC-2): one benign POST, safe for every profile,
		// SSRF-guarded; it charges its own rate-gate tick per request.
		if f := engine.LLMCanaryProbe(wd, u, tick.C); f != nil {
			fnd = append(fnd, *f)
		}
		<-tick.C
		if f := engine.CORSDifferential(wd, u); f != nil {
			fnd = append(fnd, *f)
		}
		if prof.Adversarial() {
			fnd = append(fnd, engine.RunAdversarialStage(wd, u, lh, oast, tick)...)
		}
		if c := engine.CVELookup(u, lh.Server); c != nil {
			fnd = append(fnd, *c)
		}
		// runtime capability planner: discovered capabilities trigger follow-up
		// probes and persisted attack-graph edges (adversarial profile).
		if prof.Adversarial() {
			fnd = append(fnd, engine.RunPlanner(wd, netsec.HostOf(u), fnd)...)
		}
		// persist incrementally + thread-safe so a run killed by a time cap keeps
		// its partial findings (no write-at-end data loss).
		mu.Lock()
		inScopeURLs = append(inScopeURLs, u)
		for i := range fnd {
			seq++
			fnd[i].ID = fmt.Sprintf("F%03d", seq)
			finding.Classify(&fnd[i])
			finding.AddFinding(wd, fnd[i])
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
		record := func(f finding.Finding) {
			mu.Lock()
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			finding.Classify(&f)
			finding.AddFinding(wd, f)
			mu.Unlock()
		}
		// JWT inspection of the supplied bearer token (once)
		for _, f := range engine.JWTInspect(*authToken) {
			record(f)
		}
		for _, u := range inScopeURLs {
			for _, f := range engine.CheckAuthenticated(u, authHeaders) {
				record(f)
			}
			if len(credB) > 0 {
				if f := engine.AuthzDifferential(wd, u, authHeaders, credB); f != nil {
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
		for _, f := range engine.RunDeep(wd, inScopeURLs) {
			mu.Lock()
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			finding.Classify(&f)
			finding.AddFinding(wd, f)
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
		if f := engine.ScanArtifactForInjection(art.path, art.label); f != nil {
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			finding.AddFinding(wd, *f)
			fmt.Printf("  [prompt-injection] flagged in %s — recorded as finding\n", art.label)
		}
	}

	// DNS hygiene + object-storage enumeration + edge recon run once per apex.
	if apex := engine.RegistrableDomain(netsec.HostOf(target)); apex != "" {
		apexFindings := engine.DNSHygiene(apex)
		if prof.Adversarial() {
			apexFindings = append(apexFindings, engine.EnumObjectStorage(wd, apex, names)...)
			if _, edgeFindings := engine.RunEdgeRecon(wd, target, prof); len(edgeFindings) > 0 {
				apexFindings = append(apexFindings, edgeFindings...)
			}
		}
		for _, f := range apexFindings {
			seq++
			f.ID = fmt.Sprintf("F%03d", seq)
			finding.Classify(&f)
			finding.AddFinding(wd, f)
		}
	}
	engine.WriteAdvStats(wd)
	finding.WriteRunMeta(wd, target, started, finding.LoadWorkFindings(wd), *deep, *intrusive)
	if _, err := report.SignRunManifest(wd); err == nil {
		fmt.Println("run attestation signed (ed25519): run-attestation.sig")
	}
	if _, err := report.SignEvidenceChain(wd); err == nil {
		fmt.Println("evidence chain signed (ed25519): evidence-chain.sig")
	}
	fmt.Printf("\n%d findings -> %s\n", total, finding.WorkFindings(wd))
	fmt.Println("Remediation per finding: secskills kb <class>. Report: secskills report --render", target)
	if *save {
		if path, err := finding.WriteRun(target, wd, "full"); err == nil {
			fmt.Printf("run saved: %s\n", path)
		}
	}
	return nil
}

func cmdSandbox(args []string) error {
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	port := fs.Int("port", 8080, "port the containerized app listens on")
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills sandbox <build-context> --confirm [--port N]")
	}
	if !tooling.Has("docker") {
		return fmt.Errorf("sandbox mode requires Docker (not installed) — refusing, never fakes isolation. Install: secskills doctor --tools docker")
	}
	ctx := pos[0]
	if err := scope.GateNotice("sandbox", ctx, *confirm); err != nil {
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

	wd, err := workspace.Workdir("sandbox-" + tag)
	if err != nil {
		return err
	}
	workspace.WriteScope(wd, []string{netsec.HostOf(url)})
	var fnd []finding.Finding
	fnd = append(fnd, engine.CheckSecurityHeaders(url)...)
	fnd = append(fnd, engine.CheckExposure(url)...)
	for i := range fnd {
		fnd[i].ID = fmt.Sprintf("SBX-%02d", i+1)
		finding.AddFinding(wd, fnd[i])
	}
	fmt.Printf("[sandbox] %d findings against isolated instance -> %s\n", len(fnd), finding.WorkFindings(wd))
	return nil
}
