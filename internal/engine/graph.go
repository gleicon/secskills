package engine

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
	"golang.org/x/net/publicsuffix"
)

// The cross-domain exploration graph maps how seed domains relate to OTHER
// external domains via passive OSINT — certificate SANs, CNAMEs, and shared
// hosting org/ASN. It is DISCOVERY ONLY: discovered domains are never probed or
// tested. Every edge records why the pivot exists and every node records its
// authorization status, answering the CISO's question "why did you touch these,
// and were they authorized?" before anything is tested.

// GraphEdge links two domains with the evidence that relates them.
type GraphEdge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"` // cert-SAN | CNAME | shared-org | shared-ASN
	Evidence     string `json:"evidence"`
	Confidence   string `json:"confidence"` // High | Medium | Low
}

// GraphNode is a domain in the exploration graph; only seeds are in scope.
type GraphNode struct {
	Domain        string `json:"domain"`
	Seed          bool   `json:"seed"`
	Authorization string `json:"authorization"` // in-scope | UNCONFIRMED
}

// ExploreGraph is the cross-domain OSINT graph written by `secskills graph`.
type ExploreGraph struct {
	Generated string      `json:"generated"`
	Seeds     []string    `json:"seeds"`
	Nodes     []GraphNode `json:"nodes"`
	Edges     []GraphEdge `json:"edges"`
}

// RenderGraphMarkdown produces a mermaid diagram + an edge table with provenance
// and a node table with authorization status.
func RenderGraphMarkdown(g ExploreGraph) string {
	var b strings.Builder
	b.WriteString("# Attack Surface Exploration Graph\n\n")
	b.WriteString("_Passive OSINT pivots only. Discovered domains are NOT tested; each requires scope confirmation._\n\n")
	b.WriteString("```mermaid\ngraph LR\n")
	id := func(d string) string { return strings.NewReplacer(".", "_", "-", "_").Replace(d) }
	for _, n := range g.Nodes {
		label := n.Domain
		shape0, shape1 := "([", "])"
		if n.Seed {
			shape0, shape1 = "[", "]" // seeds as boxes
			label = n.Domain + " (seed)"
		} else if strings.HasPrefix(n.Authorization, "UNCONFIRMED") {
			label = n.Domain + " (unconfirmed)"
		}
		b.WriteString(fmt.Sprintf("  %s%s%q%s\n", id(n.Domain), shape0, label, shape1))
	}
	for _, e := range g.Edges {
		b.WriteString(fmt.Sprintf("  %s -->|%s| %s\n", id(e.From), e.Relationship, id(e.To)))
	}
	b.WriteString("```\n\n")

	b.WriteString("## Pivots (why each domain was surfaced)\n\n")
	b.WriteString("| From | Relationship | To | Evidence | Confidence |\n|------|-------------|----|----------|-----------|\n")
	for _, e := range g.Edges {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", e.From, e.Relationship, e.To, e.Evidence, e.Confidence))
	}
	b.WriteString("\n## Nodes (authorization status)\n\n")
	b.WriteString("| Domain | Type | Authorization |\n|--------|------|---------------|\n")
	for _, n := range g.Nodes {
		typ := "discovered pivot"
		if n.Seed {
			typ = "seed"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", n.Domain, typ, n.Authorization))
	}
	b.WriteString("\n**Only seed and in-scope nodes were tested. UNCONFIRMED nodes are reported for awareness and must be scope-confirmed before assessment.**\n")
	return b.String()
}

// IsInfraDomain reports whether a registrable domain is CDN/CA/cloud
// infrastructure (shared-cert noise, not an ownership pivot).
func IsInfraDomain(d string) bool {
	for _, s := range []string{
		"cloudflaressl.com", "cloudflare.com", "cloudfront.net", "azionedge.net", "azion.com",
		"akamai.net", "akamaiedge.net", "fastly.net", "fastlySSL.net", "sni.net",
		"amazonaws.com", "azureedge.net", "windows.net", "googleusercontent.com", "gstatic.com",
		"google.com", "letsencrypt.org", "digicert.com", "sectigo.com", "globalsign.com",
		"herokuapp.com", "netlify.app", "vercel.app", "github.io", "wixsite.com",
	} {
		if d == s {
			return true
		}
	}
	return strings.Contains(d, "cdn") || strings.Contains(d, "edge")
}

// DigShort returns `dig +short` output for name/rr, or "" without dig.
func DigShort(name, rr string) string {
	if _, err := exec.LookPath("dig"); err != nil {
		return ""
	}
	out, _ := tooling.RunCmdTimeout(6*time.Second, "dig", "+short", rr, name)
	line := strings.TrimSpace(textutil.FirstLine(strings.TrimSpace(string(out))))
	return strings.TrimSuffix(strings.ToLower(line), ".")
}

// FirstOrg returns the first "Organization:" value in Shodan CLI output.
func FirstOrg(shodanOut string) string {
	for _, line := range strings.Split(shodanOut, "\n") {
		if strings.Contains(strings.ToLower(line), "organization:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

// RegistrableDomain returns the registrable domain (eTLD+1) using the Public
// Suffix List (golang.org/x/net/publicsuffix) — correct for .com.br, .co.uk, etc.
// Returns "" for junk / non-hostnames (the PSL lookup rejects them).
func RegistrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, " /:@\"'[]{}") {
		return ""
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return d
}
