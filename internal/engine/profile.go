package engine

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
)

// ProfileSubs enumerates subdomains passively (subfinder, else crt.sh).
func ProfileSubs(target string) []string {
	if tooling.Has("subfinder") {
		out, _ := tooling.RunCmdTimeout(90*time.Second, "subfinder", "-d", target, "-silent", "-all")
		var s []string
		for _, l := range strings.Fields(string(out)) {
			s = append(s, strings.ToLower(l))
		}
		if len(s) > 0 {
			return s
		}
	}
	var s []string
	for _, h := range fetch.CrtshNames(target) {
		if strings.HasSuffix(h, target) {
			s = append(s, h)
		}
	}
	return s
}

// SignalCounts tallies environment and service hints in subdomain names.
func SignalCounts(subs []string) (env, svc map[string]int) {
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

// DigOut returns `dig +short` output for name/rr, or "" without dig.
func DigOut(name, rr string) string {
	if _, err := exec.LookPath("dig"); err != nil {
		return ""
	}
	out, _ := tooling.RunCmdTimeout(8*time.Second, "dig", "+short", rr, name)
	return strings.TrimSpace(string(out))
}

// CDNFromCNAME names the CDN a CNAME points to, or "".
func CDNFromCNAME(c string) string {
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

// ProviderFromNS names the DNS provider from an NS record, or "".
func ProviderFromNS(ns string) string {
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

// ProviderFromMX names the mail provider from an MX record, or "".
func ProviderFromMX(mx string) string {
	l := strings.ToLower(mx)
	switch {
	case strings.Contains(l, "google"):
		return "Google Workspace"
	case strings.Contains(l, "outlook") || strings.Contains(l, "protection.outlook"):
		return "Microsoft 365"
	default:
		return textutil.FirstLine(mx)
	}
}

// ParseShodanBrief extracts /24s, organizations and SaaS names from Shodan output.
func ParseShodanBrief(s string) (ips, orgs, saas []string) {
	ipset, orgset, saasset := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range textutil.IPRe.FindAllStringSubmatch(s, -1) {
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

// KvLine renders the n largest counts as "k ×v · …".
func KvLine(m map[string]int, n int) string {
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
