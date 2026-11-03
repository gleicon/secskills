package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/probe"
)

func jsonUnmarshalLine(line string, v any) bool { return json.Unmarshal([]byte(line), v) == nil }

func atoiSafe(s string) int { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }

// cmdPrefixReport renders an operator-facing exposure report for one swept
// block from its stored artifacts (observations.jsonl + leaks.jsonl). It is a
// read-only summary of what was already observed — it sends no traffic. The
// output is engagement data (host IPs, exposure locations) and is written to a
// file, never published; credential VALUES are never included (only the fact of
// exposure and the key names, so an administrator can rotate).
func cmdPrefixReport(args []string) error {
	fs := flag.NewFlagSet("prefix-report", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with observations.jsonl (and optional leaks.jsonl)")
	out := fs.String("output", "", "write the report here (default <workdir>/exposure-report.md)")
	label := fs.String("label", "", "scope label for the heading (e.g. AS64500 203.0.113.0/24)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("usage: secskills prefix-report --workdir <dir> [--label ...] [--output file]")
	}
	// Prefer the enriched observations (product/version) when an enrich pass has
	// run; fall back to the raw sweep output.
	obsPath := filepath.Join(*wd, "enriched-observations.jsonl")
	if _, err := os.Stat(obsPath); err != nil {
		obsPath = filepath.Join(*wd, "observations.jsonl")
	}
	obs, err := probe.Load(obsPath)
	if err != nil {
		return fmt.Errorf("load observations: %w", err)
	}
	leaks := loadLeaks(filepath.Join(*wd, "leaks.jsonl"))    // optional
	dbc := loadDBChecks(filepath.Join(*wd, "dbcheck.jsonl")) // optional

	report := renderPrefixReport(*label, obs, leaks, dbc, loadKEVForEnrich(), loadCandidates(filepath.Join(*wd, "candidates.jsonl")))
	target := *out
	if target == "" {
		target = filepath.Join(*wd, "exposure-report.md")
	}
	if err := os.WriteFile(target, []byte(report), 0o600); err != nil {
		return err
	}
	fmt.Printf("exposure report -> %s (%d bytes)\n", target, len(report))
	return nil
}

func loadLeaks(path string) []leakFinding {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []leakFinding
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var f leakFinding
		if jsonUnmarshalLine(ln, &f) {
			out = append(out, f)
		}
	}
	return out
}

// hostPorts groups observations into a per-host port/service map.
func hostPorts(obs []Observation) map[string][]Observation {
	m := map[string][]Observation{}
	for _, o := range obs {
		m[o.IP] = append(m[o.IP], o)
	}
	for ip := range m {
		sort.Slice(m[ip], func(i, j int) bool { return m[ip][i].Port < m[ip][j].Port })
	}
	return m
}

// datastorePorts are services that must not be internet-reachable; their mere
// exposure is a finding regardless of version (defense in depth).
var datastorePorts = map[string]bool{
	"mysql": true, "postgresql": true, "redis": true, "mongodb": true,
	"elasticsearch": true, "rdp": true,
}

func loadDBChecks(path string) []dbResult {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []dbResult
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var r dbResult
		if jsonUnmarshalLine(ln, &r) {
			out = append(out, r)
		}
	}
	return out
}

func loadCandidates(path string) []intel.Candidate {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []intel.Candidate
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var c intel.Candidate
		if jsonUnmarshalLine(ln, &c) {
			out = append(out, c)
		}
	}
	return out
}

// renderCandidates writes the version-inferred CVE candidate subsection: the
// KEV-urgent matches in full (the actionable feed), the rest as a counted
// summary, with the version-inferred caveat stated once.
func renderCandidates(w func(string, ...any), cands []intel.Candidate) {
	if len(cands) == 0 {
		w("> Precise CVE-by-version matching: run `secskills feed nvd --product <p>` then `cvematch`.\n\n")
		return
	}
	var urgent []intel.Candidate
	for _, c := range cands {
		if c.UrgentFeed {
			urgent = append(urgent, c)
		}
	}
	w("### Version-inferred CVE candidates\n\n")
	w("Matched by CPE version range against NVD. **Version-inferred** — a distro backport may have ")
	w("patched the CVE behind an unchanged version string, so each is a lead to confirm, not a finding.\n\n")
	w("- Total candidates: **%d**\n", len(cands))
	w("- **KEV-listed (urgent — exploited in the wild): %d**\n\n", len(urgent))
	if len(urgent) > 0 {
		sort.Slice(urgent, func(i, j int) bool {
			if urgent[i].CVE != urgent[j].CVE {
				return urgent[i].CVE < urgent[j].CVE
			}
			return ipLess(urgent[i].AssetIP, urgent[j].AssetIP)
		})
		w("| Host | CVE (KEV) | Finding |\n|---|---|---|\n")
		for _, c := range urgent {
			w("| `%s` | %s | %s |\n", c.AssetIP, c.CVE, mdEscape(c.Claim))
		}
		w("\n")
	}
	w("> The non-KEV remainder is a long tail of historical version matches — triage by KEV, then EPSS. ")
	w("Confirm each against the host's distro backport before action.\n\n")
}

func renderPrefixReport(label string, obs []Observation, leaks []leakFinding, dbc []dbResult, kev []KEVEntry, cands []intel.Candidate) string {
	if label == "" {
		label = "scanned prefix"
	}
	hp := hostPorts(obs)
	svcCount := map[string]int{}
	for _, o := range obs {
		svcCount[orUnknown(o.Service)]++
	}

	// Split leaks: credential/data exposures (critical) vs banners (context).
	var critical []leakFinding
	for _, f := range leaks {
		if f.Kind != "banner" {
			critical = append(critical, f)
		}
	}
	// Exposed datastores from observations.
	type ds struct {
		ipport, svc string
	}
	var datastores []ds
	for _, o := range obs {
		if datastorePorts[o.Service] {
			datastores = append(datastores, ds{fmt.Sprintf("%s:%d", o.IP, o.Port), o.Service})
		}
	}
	sort.Slice(datastores, func(i, j int) bool { return datastores[i].ipport < datastores[j].ipport })

	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("# External Exposure Report — %s\n\n", label)
	w("**Generated:** %s  \n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	if len(dbc) > 0 {
		w("**Method:** non-destructive, read-only (TCP connect + HTTP GET), plus an owner-authorized ")
		w("datastore authentication check (`dbcheck`): a single liveness command and documented *default* ")
		w("credentials only — no brute force, no data read, no writes.  \n")
	} else {
		w("**Method:** non-destructive, unauthenticated, read-only (TCP connect + HTTP GET). ")
		w("No credentials, no default-credential attempts, no writes (D-4).  \n")
	}
	w("**Sensitivity:** contains host addresses and exposure locations — share only with the asset owner's administrators. Credential *values* are deliberately omitted.\n\n")

	w("## Summary\n\n")
	w("- Live hosts: **%d**\n", len(hp))
	w("- Reachable services: **%d**\n", len(obs))
	w("- Critical exposures (data/credential leaks): **%d**\n", len(critical))
	w("- Internet-reachable datastores/RDP: **%d**\n\n", len(datastores))
	w("Services by type: ")
	w("%s\n\n", svcTally(svcCount))

	// 1. Critical — data & credential leaks.
	w("## 1. Critical — data & credential exposure (fix today)\n\n")
	if len(critical) == 0 {
		w("_None found._\n\n")
	} else {
		w("| Host | Issue | Detail (redacted) | Action |\n|---|---|---|---|\n")
		sort.Slice(critical, func(i, j int) bool {
			if critical[i].IP != critical[j].IP {
				return critical[i].IP < critical[j].IP
			}
			return critical[i].Kind < critical[j].Kind
		})
		for _, f := range critical {
			w("| `%s:%d` | **%s** | %s | %s |\n", f.IP, f.Port, f.Kind, mdEscape(f.Evidence), leakAction(f.Kind))
		}
		w("\n")
		if hasKind(critical, "exposed-dotenv") {
			w("> A served `.env` means every secret in it must be treated as compromised. ")
			w("Rotate **all** listed keys (DB passwords, APP_KEY, MAIL_DSN, API keys) and remove the file from the web root. ")
			w("An adjacent exposed `.git` often lets an attacker reconstruct full source and history — audit for leaked secrets in commits.\n\n")
		}
	}

	// 2. Exposed datastores, annotated with the authentication posture when a
	// dbcheck pass was run (OPEN-NOAUTH / DEFAULT-CRED are critical).
	dbStatus := map[string]dbResult{}
	for _, r := range dbc {
		dbStatus[fmt.Sprintf("%s:%d", r.IP, r.Port)] = r
	}
	w("## 2. Internet-reachable datastores / remote access\n\n")
	if len(datastores) == 0 {
		w("_None found._\n\n")
	} else {
		w("These ports should sit behind a security group / firewall, not on the public internet.\n\n")
		if len(dbc) > 0 {
			w("Authentication posture verified read-only (`dbcheck`): **OPEN-NOAUTH** and **DEFAULT-CRED** are critical.\n\n")
			w("| Endpoint | Service | Auth posture | Action |\n|---|---|---|---|\n")
			for _, d := range datastores {
				r, ok := dbStatus[d.ipport]
				posture, action := "not tested", "restrict to private network; require auth"
				if ok {
					posture = r.Status
					switch r.Status {
					case "OPEN-NOAUTH":
						posture = "**OPEN — NO AUTH**"
						action = "**isolate now**; enable authentication; assume data read/altered"
					case "DEFAULT-CRED":
						posture = "**DEFAULT CREDENTIAL**"
						action = "**change the default now** (" + mdEscape(r.Detail) + "); restrict network"
					case "AUTH-ENFORCED":
						action = "move behind firewall; auth is on (good)"
					}
				}
				w("| `%s` | %s | %s | %s |\n", d.ipport, d.svc, posture, action)
			}
		} else {
			w("| Endpoint | Service | Action |\n|---|---|---|\n")
			for _, d := range datastores {
				w("| `%s` | %s | restrict to private network; require auth; rotate if it was open unauthenticated |\n", d.ipport, d.svc)
			}
		}
		w("\n")
	}

	// 3. Software inventory + KEV leads.
	w("## 3. Software inventory and CVE status\n\n")
	prodVer := map[string]int{}
	withVer := 0
	for _, o := range obs {
		if o.Product == "" {
			continue
		}
		label := o.Product
		if o.Version != "" {
			label += " " + o.Version
			withVer++
		}
		prodVer[label]++
	}
	if len(prodVer) == 0 {
		w("Versions not yet enriched — run `secskills enrich` to populate product/version, ")
		w("then regenerate this report. Observed web servers: %s.\n\n", serverList(leaks))
	} else {
		w("Versions fingerprinted on **%d** services (SSH/HTTP/SMTP banners, MySQL handshake).\n\n", withVer)
		w("| Product / version | Count |\n|---|---|\n")
		type kv struct {
			k string
			v int
		}
		var rows []kv
		for k, v := range prodVer {
			rows = append(rows, kv{k, v})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].v != rows[j].v {
				return rows[i].v > rows[j].v
			}
			return rows[i].k < rows[j].k
		})
		for i, r := range rows {
			if i >= 20 {
				w("| _(%d more)_ | |\n", len(rows)-20)
				break
			}
			w("| %s | %d |\n", r.k, r.v)
		}
		w("\n")
		if len(kev) > 0 {
			var leads []string
			seen := map[string]bool{}
			for _, o := range obs {
				if o.Product == "" || seen[o.Product] {
					continue
				}
				if hits := kevProductHits(o.Product, kev); len(hits) > 0 {
					seen[o.Product] = true
					leads = append(leads, fmt.Sprintf("`%s` (KEV e.g. %s)", o.Product, hits[0]))
				}
			}
			if len(leads) > 0 {
				w("**KEV name-level leads** (product appears in CISA KEV — confirm by version before acting): %s.\n\n", strings.Join(leads, "; "))
			} else {
				w("No observed product name matches the KEV catalog.\n\n")
			}
		}
		renderCandidates(w, cands)
	}

	// 4. Per-host inventory.
	w("## 4. Host inventory\n\n")
	w("| Host | Open services |\n|---|---|\n")
	ips := make([]string, 0, len(hp))
	for ip := range hp {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })
	for _, ip := range ips {
		var parts []string
		for _, o := range hp[ip] {
			parts = append(parts, fmt.Sprintf("%d/%s", o.Port, orUnknown(o.Service)))
		}
		w("| `%s` | %s |\n", ip, strings.Join(parts, ", "))
	}
	w("\n")

	// 5. Remediation checklist.
	w("## 5. Remediation checklist\n\n")
	w("1. Remove `.env`, `.git/`, and any backup/config files from web-served directories; block dotfiles at the proxy.\n")
	w("2. Rotate every credential that appeared in an exposed `.env` or git history — assume compromise.\n")
	w("3. Move datastore and RDP ports behind a firewall / security group; never expose them publicly.\n")
	w("4. Require authentication on every datastore (Redis `requirepass`, Mongo auth, ES security).\n")
	w("5. Re-scan to confirm closure; this report is reproducible with `secskills prefix-report`.\n")
	return b.String()
}

func svcTally(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v > s[j].v })
	var parts []string
	for _, e := range s {
		parts = append(parts, fmt.Sprintf("%s %d", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}

func serverList(leaks []leakFinding) string {
	seen := map[string]bool{}
	var out []string
	for _, f := range leaks {
		if f.Kind == "banner" && f.Server != "" {
			s := strings.Split(f.Server, "/")[0]
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "none captured"
	}
	return strings.Join(out, ", ")
}

func leakAction(kind string) string {
	switch kind {
	case "exposed-dotenv":
		return "remove file; **rotate all secrets**"
	case "exposed-vcs":
		return "remove `.git` from web root; audit history for secrets"
	case "dir-listing":
		return "disable autoindex"
	case "server-status":
		return "restrict or disable mod_status"
	case "es-open-indices":
		return "enable ES authentication; restrict network"
	case "redis-unauth":
		return "set `requirepass`; bind to private interface"
	}
	return "review"
}

func hasKind(fs []leakFinding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 4 || len(pb) != 4 {
		return a < b
	}
	for i := 0; i < 4; i++ {
		x, y := atoiSafe(pa[i]), atoiSafe(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}
