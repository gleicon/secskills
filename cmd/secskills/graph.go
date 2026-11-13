package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/scope"
	"github.com/gleicon/secskills/internal/tooling"
	"github.com/gleicon/secskills/internal/workspace"
)

func cmdGraph(args []string) error {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	outDir := fs.String("output", ".", "directory for graph.json + graph.md")
	pos, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills graph <seed-domain> [more-seeds...] [--output dir]")
	}
	seeds := make([]string, 0, len(pos))
	seedSet := map[string]bool{}
	for _, s := range pos {
		d := engine.RegistrableDomain(netsec.HostOf(s))
		if !seedSet[d] {
			seedSet[d] = true
			seeds = append(seeds, d)
		}
	}

	g := engine.ExploreGraph{Generated: finding.NowRFC(), Seeds: seeds}
	nodes := map[string]*engine.GraphNode{}
	node := func(d string, seed bool) {
		if nodes[d] == nil {
			auth := "UNCONFIRMED — requires scope confirmation before testing"
			if ok, _ := scope.ScopeAuthorizes(d); ok || seedSet[d] {
				if seedSet[d] {
					auth = "seed (authorized target)"
				} else if ok {
					auth = "in-scope (scope file)"
				}
			}
			nodes[d] = &engine.GraphNode{Domain: d, Seed: seed, Authorization: auth}
		}
		if seed {
			nodes[d].Seed = true
		}
	}
	for _, s := range seeds {
		node(s, true)
	}

	addEdge := func(from, to, rel, evidence, conf string) {
		to = engine.RegistrableDomain(to)
		if to == "" || to == from || strings.HasSuffix(to, ".arpa") {
			return
		}
		node(to, false)
		g.Edges = append(g.Edges, engine.GraphEdge{From: from, To: to, Relationship: rel, Evidence: evidence, Confidence: conf})
	}

	for _, seed := range seeds {
		fmt.Fprintf(os.Stderr, "[graph] pivoting from %s (OSINT only)\n", seed)
		// 1. certificate SANs (crt.sh, JSON). Co-SANs on a shared CDN/CA certificate
		// are NOT ownership — they are frequently unrelated co-tenants. Treat as a
		// LOW-confidence "shared-cert" signal, exclude CDN/CA infra domains, and cap.
		seen := map[string]bool{}
		sanCount := 0
		for _, h := range fetch.CrtshNames(seed) {
			rd := engine.RegistrableDomain(h)
			if rd == "" || rd == seed || seedSet[rd] || seen[rd] || engine.IsInfraDomain(rd) {
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
			if cn := engine.DigShort(name, "CNAME"); cn != "" {
				addEdge(seed, cn, "CNAME", name+" is a CNAME to "+cn, "High")
			}
		}
		// 3. shared hosting org / ASN via Shodan (if key)
		if tooling.ShodanReady() {
			if out, err := tooling.RunCmdTimeout(20*time.Second, "shodan", "domain", seed); err == nil {
				if org := engine.FirstOrg(string(out)); org != "" {
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
	md := engine.RenderGraphMarkdown(g)
	os.WriteFile(filepath.Join(*outDir, "graph.md"), []byte(md), 0o644)

	fmt.Printf("== exploration graph: %d nodes, %d edges ==\n", len(g.Nodes), len(g.Edges))
	fmt.Print(md)
	fmt.Printf("\nWritten: %s/graph.json, %s/graph.md\n", *outDir, *outDir)
	fmt.Println("NOTE: discovered domains are NOT tested. Confirm ownership/scope before assessing any UNCONFIRMED node.")
	return nil
}
