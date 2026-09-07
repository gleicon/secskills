package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// cmdProfile gathers PASSIVE pre-engagement intelligence for a target — OSINT
// only, no HTTP traffic to the target — so the intake interview (secskills-intake)
// can be informed rather than asking the operator what research can answer.
// Sources: subfinder (passive), crt.sh, dnsx (DNS resolution + CNAME), Shodan
// (if key). Output is a Markdown brief to stdout or --output.
func cmdProfile(args []string) error {
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	output := fs.String("output", "", "write the brief to this path (default stdout)")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills profile <domain> [--output brief.md]")
	}
	target := hostOf(pos[0])
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	p("# Pre-Engagement Profile — %s\n\n", target)
	p("_Passive OSINT only — no traffic sent to the target. Generated %s._\n\n", nowRFC())

	// 1. subdomains (passive)
	subs := profileSubs(target)
	p("## Attack surface (passive enumeration)\n\n")
	p("- Subdomains discovered: **%d**\n", len(subs))
	envs, svcs := signalCounts(subs)
	if len(envs) > 0 {
		p("- Environment tiers in DNS: %s\n", kvLine(envs, 8))
	}
	if len(svcs) > 0 {
		p("- Service/infra signals: %s\n", kvLine(svcs, 12))
	}
	p("\n")

	// 2. DNS + CDN/WAF (from CNAME, no target HTTP)
	p("## DNS & edge\n\n")
	cname := digOut(target, "CNAME")
	ns := digOut(target, "NS")
	mx := digOut(target, "MX")
	if cname != "" {
		p("- Apex CNAME: `%s` — edge/CDN: **%s**\n", cname, cdnFromCNAME(cname))
	}
	if ns != "" {
		p("- Nameservers: %s (provider: %s)\n", firstLine(ns), providerFromNS(ns))
	}
	if mx != "" {
		p("- Mail: %s\n", providerFromMX(mx))
	}
	p("\n")

	// 3. Shodan (if key)
	p("## Shodan OSINT\n\n")
	if shodanReady() {
		out, _ := runCmdTimeout(25*time.Second, "shodan", "domain", target)
		ips, orgs, saas := parseShodanBrief(string(out))
		if len(ips) > 0 {
			p("- IP blocks / ASN scope: %s\n", strings.Join(cap8(ips), ", "))
		}
		if len(orgs) > 0 {
			p("- Hosting org(s): %s\n", strings.Join(orgs, ", "))
		}
		if len(saas) > 0 {
			p("- Third-party SaaS (DNS TXT): %s\n", strings.Join(saas, ", "))
		}
		if len(ips) == 0 && len(saas) == 0 {
			p("- Shodan returned no domain data (not indexed).\n")
		}
	} else {
		p("- **Not available** — no Shodan key (set `SHODAN_API_KEY` or `shodan init`).\n")
	}
	p("\n")

	// 4. Open questions the interview must still resolve
	p("## Still to confirm (interview)\n\n")
	p("- [ ] Written authorization + engagement type (black/grey/white-box)\n")
	p("- [ ] Exact in-scope apexes/subdomains and any **out-of-scope** hosts\n")
	p("- [ ] IP ranges/ASN in scope for network-layer testing\n")
	p("- [ ] Target class: web / API / mobile / LLM-agent (drives OWASP framework)\n")
	p("- [ ] Credentials for authenticated testing (else marked not-available)\n")
	p("- [ ] Rules of engagement: intrusive allowed? rate limit? test window? prod vs staging?\n")
	p("- [ ] Deliverable location + PII handling\n")

	brief := b.String()
	if *output == "" {
		fmt.Print(brief)
		return nil
	}
	return os.WriteFile(*output, []byte(brief), 0o644)
}

func profileSubs(target string) []string {
	if has("subfinder") {
		out, _ := runCmdTimeout(90*time.Second, "subfinder", "-d", target, "-silent", "-all")
		var s []string
		for _, l := range strings.Fields(string(out)) {
			s = append(s, strings.ToLower(l))
		}
		if len(s) > 0 {
			return s
		}
	}
	var s []string
	for _, h := range crtshNames(target) {
		if strings.HasSuffix(h, target) {
			s = append(s, h)
		}
	}
	return s
}

func signalCounts(subs []string) (env, svc map[string]int) {
	env, svc = map[string]int{}, map[string]int{}
	for _, s := range subs {
		l := strings.ToLower(s)
		for _, e := range []string{"preprod", "staging", "dev", "qa", "sandbox", "test", "homolog", "internal"} {
			if strings.Contains(l, e) {
				env[e]++
			}
		}
		for _, k := range []string{"api", "sso", "iam", "admin", "auth", "login", "console", "gateway", "graphql", "vault", "registry", "grafana", "prometheus", "argocd", "gitlab", "jenkins", "keycloak", "harbor"} {
			if strings.Contains(l, k) {
				svc[k]++
			}
		}
	}
	return
}

func digOut(name, rr string) string {
	if _, err := exec.LookPath("dig"); err != nil {
		return ""
	}
	out, _ := runCmdTimeout(8*time.Second, "dig", "+short", rr, name)
	return strings.TrimSpace(string(out))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func cdnFromCNAME(c string) string {
	l := strings.ToLower(c)
	switch {
	case strings.Contains(l, "azion"):
		return "Azion"
	case strings.Contains(l, "cloudfront"):
		return "AWS CloudFront"
	case strings.Contains(l, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(l, "akamai"):
		return "Akamai"
	case strings.Contains(l, "fastly"):
		return "Fastly"
	case strings.Contains(l, "azureedge"):
		return "Azure CDN"
	default:
		return "unknown / origin"
	}
}

func providerFromNS(ns string) string {
	l := strings.ToLower(ns)
	switch {
	case strings.Contains(l, "googledomains") || strings.Contains(l, "google"):
		return "Google Cloud DNS"
	case strings.Contains(l, "awsdns"):
		return "AWS Route 53"
	case strings.Contains(l, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(l, "azure"):
		return "Azure DNS"
	default:
		return "other"
	}
}

func providerFromMX(mx string) string {
	l := strings.ToLower(mx)
	switch {
	case strings.Contains(l, "google"):
		return "Google Workspace"
	case strings.Contains(l, "outlook") || strings.Contains(l, "protection.outlook"):
		return "Microsoft 365"
	default:
		return firstLine(mx)
	}
}

func parseShodanBrief(s string) (ips, orgs, saas []string) {
	ipset, orgset, saasset := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range ipRe.FindAllStringSubmatch(s, -1) {
		ipset[m[1]+".0/24"] = true
	}
	for _, line := range strings.Split(s, "\n") {
		ll := strings.ToLower(line)
		if strings.Contains(ll, "organization:") {
			orgset[strings.TrimSpace(strings.SplitN(line, ":", 2)[1])] = true
		}
		for _, k := range []string{"atlassian", "figma", "google-site", "apple-domain", "adobe", "aws", "cisco", "zoom", "slack"} {
			if strings.Contains(ll, k) {
				saasset[k] = true
			}
		}
	}
	for k := range ipset {
		ips = append(ips, k)
	}
	for k := range orgset {
		orgs = append(orgs, k)
	}
	for k := range saasset {
		saas = append(saas, k)
	}
	sort.Strings(ips)
	sort.Strings(orgs)
	sort.Strings(saas)
	return
}

func cap8(s []string) []string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func kvLine(m map[string]int, n int) string {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v > s[j].v })
	var out []string
	for i, e := range s {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s ×%d", e.k, e.v))
	}
	return strings.Join(out, " · ")
}
