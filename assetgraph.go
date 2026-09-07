package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Item 8 — Asset graph + root-cause clustering.
// Findings attach to endpoints, but operational reality is shared infrastructure:
// many hostnames front one ingress/certificate/ASN. Clustering collapses N
// endpoint observations into the small number of underlying configurations and
// states *why* they were grouped — platform diagnosis, not mere deduplication.

type assetNode struct {
	Host    string
	IP      string
	ASNHint string // /24 network as a cheap shared-infra proxy
	Server  string
	CNAME   string
}

// buildAssetNodes derives asset nodes from the live hosts, resolving IP/CNAME
// (bounded, best-effort). Shared /24 + server + CNAME suffix approximate a shared
// ingress without requiring a full ASN feed.
func buildAssetNodes(live []LiveHost) map[string]assetNode {
	nodes := map[string]assetNode{}
	for _, h := range live {
		host := hostOf(h.URL)
		n := assetNode{Host: host, Server: strings.ToLower(h.Server)}
		if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
			n.IP = ips[0]
			n.ASNHint = slash24(ips[0])
		}
		if c, err := net.LookupCNAME(host); err == nil {
			n.CNAME = strings.TrimSuffix(c, ".")
		}
		nodes[host] = n
	}
	return nodes
}

func slash24(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return ""
}

// clusterRootIssues groups the findings of each root family by shared-infra
// signature and renders the collapse with explicit grouping reasons.
func clusterRootIssues(findings []Finding, live []LiveHost) string {
	nodes := buildAssetNodes(live)
	// family -> signature -> hosts
	fam := map[string]map[string][]string{}
	famCount := map[string]int{}
	for i := range findings {
		f := &findings[i]
		root := rootFamily(f)
		if root == "" {
			continue
		}
		host := hostOf(f.Host)
		n := nodes[host]
		sig := infraSignature(n)
		if fam[root] == nil {
			fam[root] = map[string][]string{}
		}
		if !contains(fam[root][sig], host) {
			fam[root][sig] = append(fam[root][sig], host)
		}
		famCount[root]++
	}
	if len(fam) == 0 {
		return "_No clusterable root families in this run._"
	}
	fams := make([]string, 0, len(fam))
	for k := range fam {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	var b strings.Builder
	for _, root := range fams {
		groups := fam[root]
		nGroups := len(groups)
		fmt.Fprintf(&b, "### %s\n\n", root)
		fmt.Fprintf(&b, "%d observations across %d shared-configuration group(s):\n\n", famCount[root], nGroups)
		// order groups by size desc
		type grp struct {
			sig   string
			hosts []string
		}
		var gs []grp
		for sig, hosts := range groups {
			sort.Strings(hosts)
			gs = append(gs, grp{sig, hosts})
		}
		sort.Slice(gs, func(i, j int) bool { return len(gs[i].hosts) > len(gs[j].hosts) })
		gi := 0
		for _, g := range gs {
			gi++
			reason := groupReason(g.sig)
			fmt.Fprintf(&b, "- **G%d — %d asset(s)** (%s): %s\n", gi, len(g.hosts), reason, strings.Join(capList(g.hosts, 6), ", "))
		}
		b.WriteString("\n")
	}
	b.WriteString("_Grouping is by shared-infrastructure signature (resolved /24 + web server + CNAME suffix). Remediating the shared ingress/config fixes every asset in a group at once._")
	return b.String()
}

// rootFamily collapses a finding to the config it stems from.
func rootFamily(f *Finding) string {
	switch findingType(f) {
	case "tls-deprecated":
		return "Deprecated TLS / weak cipher policy (edge)"
	case "hsts-missing", "csp-missing", "nosniff-missing", "xfo-missing":
		return "Missing security-header policy (edge)"
	case "metrics-exposed", "exposure-path":
		return "Unauthenticated operational exposure"
	case "cors":
		return "Cross-origin policy"
	}
	return ""
}

func infraSignature(n assetNode) string {
	cnameSuffix := ""
	if n.CNAME != "" {
		parts := strings.Split(strings.Trim(n.CNAME, "."), ".")
		if len(parts) >= 2 {
			cnameSuffix = strings.Join(parts[len(parts)-2:], ".")
		}
	}
	return strings.Join([]string{n.ASNHint, n.Server, cnameSuffix}, "|")
}

func groupReason(sig string) string {
	parts := strings.SplitN(sig, "|", 3)
	var r []string
	if len(parts) > 0 && parts[0] != "" {
		r = append(r, "same /24 "+parts[0])
	}
	if len(parts) > 1 && parts[1] != "" {
		r = append(r, "server "+parts[1])
	}
	if len(parts) > 2 && parts[2] != "" {
		r = append(r, "CNAME "+parts[2])
	}
	if len(r) == 0 {
		return "no shared-infra signal (grouped as unclustered)"
	}
	return strings.Join(r, ", ")
}
