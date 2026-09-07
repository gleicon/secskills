package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// The cross-domain exploration graph maps how seed domains relate to OTHER
// external domains via passive OSINT — certificate SANs, CNAMEs, and shared
// hosting org/ASN. It is DISCOVERY ONLY: discovered domains are never probed or
// tested. Every edge records why the pivot exists and every node records its
// authorization status, answering the CISO's question "why did you touch these,
// and were they authorized?" before anything is tested.

type graphEdge struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"` // cert-SAN | CNAME | shared-org | shared-ASN
	Evidence     string `json:"evidence"`
	Confidence   string `json:"confidence"` // High | Medium | Low
}

type graphNode struct {
	Domain        string `json:"domain"`
	Seed          bool   `json:"seed"`
	Authorization string `json:"authorization"` // in-scope | UNCONFIRMED
}

type exploreGraph struct {
	Generated string      `json:"generated"`
	Seeds     []string    `json:"seeds"`
	Nodes     []graphNode `json:"nodes"`
	Edges     []graphEdge `json:"edges"`
}

func cmdGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	outDir := fs.String("output", ".", "directory for graph.json + graph.md")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills graph <seed-domain> [more-seeds...] [--output dir]")
	}
	seeds := make([]string, 0, len(pos))
	seedSet := map[string]bool{}
	for _, s := range pos {
		d := registrableDomain(hostOf(s))
		if !seedSet[d] {
			seedSet[d] = true
			seeds = append(seeds, d)
		}
	}

	g := exploreGraph{Generated: nowRFC(), Seeds: seeds}
	nodes := map[string]*graphNode{}
	node := func(d string, seed bool) {
		if nodes[d] == nil {
			auth := "UNCONFIRMED — requires scope confirmation before testing"
			if ok, _ := scopeAuthorizes(d); ok || seedSet[d] {
				if seedSet[d] {
					auth = "seed (authorized target)"
				} else if ok {
					auth = "in-scope (scope file)"
				}
			}
			nodes[d] = &graphNode{Domain: d, Seed: seed, Authorization: auth}
		}
		if seed {
			nodes[d].Seed = true
		}
	}
	for _, s := range seeds {
		node(s, true)
	}

	addEdge := func(from, to, rel, evidence, conf string) {
		to = registrableDomain(to)
		if to == "" || to == from || strings.HasSuffix(to, ".arpa") {
			return
		}
		node(to, false)
		g.Edges = append(g.Edges, graphEdge{From: from, To: to, Relationship: rel, Evidence: evidence, Confidence: conf})
	}

	for _, seed := range seeds {
		fmt.Fprintf(os.Stderr, "[graph] pivoting from %s (OSINT only)\n", seed)
		// 1. certificate SANs (crt.sh, JSON). Co-SANs on a shared CDN/CA certificate
		// are NOT ownership — they are frequently unrelated co-tenants. Treat as a
		// LOW-confidence "shared-cert" signal, exclude CDN/CA infra domains, and cap.
		seen := map[string]bool{}
		sanCount := 0
		for _, h := range crtshNames(seed) {
			rd := registrableDomain(h)
			if rd == "" || rd == seed || seedSet[rd] || seen[rd] || isInfraDomain(rd) {
				continue
			}
			seen[rd] = true
			sanCount++
			if sanCount > 25 {
				continue // cap noise from large multi-tenant certs
			}
			addEdge(seed, rd, "shared-cert",
				"appears on a TLS certificate alongside "+seed+" (crt.sh) — may be a shared CDN/CA multi-tenant cert, not shared ownership; validate",
				"Low")
		}
		// 2. CNAME pivots on the apex + common names
		for _, name := range []string{seed, "www." + seed, "api." + seed} {
			if cn := digShort(name, "CNAME"); cn != "" {
				addEdge(seed, cn, "CNAME", name+" is a CNAME to "+cn, "High")
			}
		}
		// 3. shared hosting org / ASN via Shodan (if key)
		if shodanReady() {
			if out, err := runCmdTimeout(20*time.Second, "shodan", "domain", seed); err == nil {
				if org := firstOrg(string(out)); org != "" {
					nodes[seed].Authorization += " · hosting: " + org
				}
			}
		}
	}

	for _, n := range nodes {
		g.Nodes = append(g.Nodes, *n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].Domain < g.Nodes[j].Domain })

	os.MkdirAll(*outDir, 0o755)
	jb, _ := json.MarshalIndent(g, "", "  ")
	os.WriteFile(filepath.Join(*outDir, "graph.json"), jb, 0o644)
	md := renderGraphMarkdown(g)
	os.WriteFile(filepath.Join(*outDir, "graph.md"), []byte(md), 0o644)

	fmt.Printf("== exploration graph: %d nodes, %d edges ==\n", len(g.Nodes), len(g.Edges))
	fmt.Print(md)
	fmt.Printf("\nWritten: %s/graph.json, %s/graph.md\n", *outDir, *outDir)
	fmt.Println("NOTE: discovered domains are NOT tested. Confirm ownership/scope before assessing any UNCONFIRMED node.")
	return nil
}

// renderGraphMarkdown produces a mermaid diagram + an edge table with provenance
// and a node table with authorization status.
func renderGraphMarkdown(g exploreGraph) string {
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

// isInfraDomain reports whether a registrable domain is CDN/CA/cloud
// infrastructure (shared-cert noise, not an ownership pivot).
func isInfraDomain(d string) bool {
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

func digShort(name, rr string) string {
	if _, err := exec.LookPath("dig"); err != nil {
		return ""
	}
	out, _ := runCmdTimeout(6*time.Second, "dig", "+short", rr, name)
	line := strings.TrimSpace(firstLine(strings.TrimSpace(string(out))))
	return strings.TrimSuffix(strings.ToLower(line), ".")
}

func firstOrg(shodanOut string) string {
	for _, line := range strings.Split(shodanOut, "\n") {
		if strings.Contains(strings.ToLower(line), "organization:") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

// registrableDomain returns the registrable domain (eTLD+1) using the Public
// Suffix List (golang.org/x/net/publicsuffix) — correct for .com.br, .co.uk, etc.
// Returns "" for junk / non-hostnames (the PSL lookup rejects them).
func registrableDomain(host string) string {
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
