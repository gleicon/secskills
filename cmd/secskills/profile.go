package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
	"github.com/gleicon/secskills/internal/workspace"
)

// cmdProfile gathers PASSIVE pre-engagement intelligence for a target — OSINT
// only, no HTTP traffic to the target — so the intake interview (secskills-intake)
// can be informed rather than asking the operator what research can answer.
// Sources: subfinder (passive), crt.sh, dnsx (DNS resolution + CNAME), Shodan
// (if key). Output is a Markdown brief to stdout or --output.
func cmdProfile(args []string) error {
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	output := fs.String("output", "", "write the brief to this path (default stdout)")
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills profile <domain> [--output brief.md]")
	}
	target := netsec.HostOf(pos[0])
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	p("# Pre-Engagement Profile — %s\n\n", target)
	p("_Passive OSINT only — no traffic sent to the target. Generated %s._\n\n", finding.NowRFC())

	// 1. subdomains (passive)
	subs := engine.ProfileSubs(target)
	p("## Attack surface (passive enumeration)\n\n")
	p("- Subdomains discovered: **%d**\n", len(subs))
	envs, svcs := engine.SignalCounts(subs)
	if len(envs) > 0 {
		p("- Environment tiers in DNS: %s\n", engine.KvLine(envs, 8))
	}
	if len(svcs) > 0 {
		p("- Service/infra signals: %s\n", engine.KvLine(svcs, 12))
	}
	p("\n")

	// 2. DNS + CDN/WAF (from CNAME, no target HTTP)
	p("## DNS & edge\n\n")
	cname := engine.DigOut(target, "CNAME")
	ns := engine.DigOut(target, "NS")
	mx := engine.DigOut(target, "MX")
	if cname != "" {
		p("- Apex CNAME: `%s` — edge/CDN: **%s**\n", cname, engine.CDNFromCNAME(cname))
	}
	if ns != "" {
		p("- Nameservers: %s (provider: %s)\n", textutil.FirstLine(ns), engine.ProviderFromNS(ns))
	}
	if mx != "" {
		p("- Mail: %s\n", engine.ProviderFromMX(mx))
	}
	p("\n")

	// 3. Shodan (if key)
	p("## Shodan OSINT\n\n")
	if tooling.ShodanReady() {
		out, _ := tooling.RunCmdTimeout(25*time.Second, "shodan", "domain", target)
		ips, orgs, saas := engine.ParseShodanBrief(string(out))
		if len(ips) > 0 {
			p("- IP blocks / ASN scope: %s\n", strings.Join(finding.CapList(ips, 8), ", "))
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
