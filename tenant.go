package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/probe"
)

// Multi-tenant delivery (spec FR-8) with tenant-scoped reads (NFR-3) and the
// cross-tenant isolation the AC-6 test asserts. In v0 a tenant is an ASN and its
// prefixes; a row belongs to the tenant whose prefixes contain its asset IP.
// Every read goes through tenantFilter, so a feed for tenant A can never carry
// tenant B's asset — the isolation is a filter with a test, not a code-review
// promise (NFR-3's wording).
type Tenant struct {
	Tenant   string   `json:"tenant"`
	ASN      int      `json:"asn"`
	Prefixes []string `json:"prefixes"`
}

func loadTenants(path string) ([]Tenant, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ts []Tenant
	if err := json.Unmarshal(b, &ts); err != nil {
		return nil, err
	}
	return ts, nil
}

func findTenant(ts []Tenant, id string) (Tenant, bool) {
	for _, t := range ts {
		if t.Tenant == id {
			return t, true
		}
	}
	return Tenant{}, false
}

// tenantOfIP returns the id of the first tenant whose prefixes contain ip, or ""
// if none. Used to attribute an observation to a tenant for fleet aggregation.
func tenantOfIP(ts []Tenant, ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, t := range ts {
		if ipInAnyPrefix(ip, t.Prefixes) {
			return t.Tenant
		}
	}
	return ""
}

// tenantFilter returns only the candidates whose asset IP falls inside the
// tenant's prefixes. This is the single choke point for tenant-scoped reads: an
// IP outside the tenant's prefixes is never returned, which is exactly what the
// AC-6 cross-tenant test checks. An unparseable or prefix-less IP is excluded,
// never leaked by default.
func tenantFilter(cands []intel.Candidate, t Tenant) []intel.Candidate {
	out := make([]intel.Candidate, 0, len(cands))
	for _, c := range cands {
		ip := net.ParseIP(c.AssetIP)
		if ip != nil && ipInAnyPrefix(ip, t.Prefixes) {
			out = append(out, c)
		}
	}
	return out
}

// TenantFeed is the per-tenant JSON delivery (FR-8). It carries only this
// tenant's findings plus a generation timestamp for the <1h latency measurement
// (NFR-1 / AC-2).
type TenantFeed struct {
	Tenant      string            `json:"tenant"`
	ASN         int               `json:"asn"`
	GeneratedAt string            `json:"generated_at"`
	Count       int               `json:"count"`
	UrgentCount int               `json:"urgent_count"`
	Findings    []intel.Candidate `json:"findings"`
}

func buildTenantFeed(t Tenant, cands []intel.Candidate, now string) TenantFeed {
	scoped := tenantFilter(cands, t)
	sort.Slice(scoped, func(i, j int) bool {
		if scoped[i].UrgentFeed != scoped[j].UrgentFeed {
			return scoped[i].UrgentFeed
		}
		if scoped[i].Score != scoped[j].Score {
			return scoped[i].Score > scoped[j].Score
		}
		return scoped[i].AssetIP < scoped[j].AssetIP
	})
	urgent := 0
	for _, c := range scoped {
		if c.UrgentFeed {
			urgent++
		}
	}
	return TenantFeed{
		Tenant: t.Tenant, ASN: t.ASN, GeneratedAt: now,
		Count: len(scoped), UrgentCount: urgent, Findings: scoped,
	}
}

// renderTenantBrief is the one-screen brief (spec FR-8 / D-10: never a PDF). It
// caps the body so the brief stays one screen; the full set is in the JSON feed.
func renderTenantBrief(f TenantFeed) string {
	const maxLines = 20
	s := fmt.Sprintf("Exposure brief — tenant %s (AS%d)  %s\n", f.Tenant, f.ASN, f.GeneratedAt)
	s += fmt.Sprintf("%d candidates, %d KEV-urgent. Version-inferred (L1): confirm before action.\n\n", f.Count, f.UrgentCount)
	shown := 0
	for _, c := range f.Findings {
		if shown >= maxLines {
			s += fmt.Sprintf("… %d more in the JSON feed.\n", f.Count-shown)
			break
		}
		mark := "   "
		if c.UrgentFeed {
			mark = "KEV"
		}
		s += fmt.Sprintf("%s %-16s %-16s epss=%.3f score=%.3f\n", mark, c.AssetIP, c.CVE, c.ScoreTerms["epss"], c.Score)
		shown++
	}
	return s
}

func cmdDeliver(args []string) error {
	fs := flag.NewFlagSet("deliver", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with candidates.jsonl")
	tenantsPath := fs.String("tenants", "", "tenants file (JSON array of {tenant,asn,prefixes})")
	tenantID := fs.String("tenant", "", "tenant id to deliver")
	webhook := fs.String("webhook", "", "optional: POST the JSON feed to this URL (SSRF-guarded)")
	out := fs.String("out", "", "feed output path (default: <workdir>/feed-<tenant>.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" || *tenantsPath == "" || *tenantID == "" {
		return fmt.Errorf("usage: secskills deliver --workdir <dir> --tenants <file> --tenant <id> [--webhook URL]")
	}
	tenants, err := loadTenants(*tenantsPath)
	if err != nil {
		return fmt.Errorf("tenants: %w", err)
	}
	t, ok := findTenant(tenants, *tenantID)
	if !ok {
		return fmt.Errorf("no tenant %q in %s", *tenantID, *tenantsPath)
	}
	cands := loadCandidates(filepath.Join(*wd, "candidates.jsonl"))
	feed := buildTenantFeed(t, cands, nowRFC())

	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(*wd, "feed-"+t.Tenant+".json")
	}
	b, _ := json.MarshalIndent(feed, "", "  ")
	// Feeds are sensitive engagement data: owner-only (0600), never published.
	if err := os.WriteFile(outPath, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("delivered: %d findings (%d KEV-urgent) -> %s\n", feed.Count, feed.UrgentCount, outPath)
	fmt.Println()
	fmt.Print(renderTenantBrief(feed))

	if *webhook != "" {
		if err := postWebhook(*webhook, b); err != nil {
			return err
		}
	}
	return nil
}

// postWebhook delivers the feed to a webhook over a TLS-VERIFYING client (the
// feed is sensitive, so the connection must not be MITM-readable), keeping the
// SSRF dial guard and no-redirect policy. It requires https and never logs the
// URL's path/query, which routinely carry a secret token (e.g. Slack webhooks) —
// only scheme+host is printed.
func postWebhook(webhook string, body []byte) error {
	u, err := url.Parse(webhook)
	if err != nil {
		return fmt.Errorf("invalid webhook URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("webhook must be https (got %q) — the feed is sensitive", u.Scheme)
	}
	safe := u.Scheme + "://" + u.Host
	guard := func(u string) error { return probe.SafeURL(u, false) }
	client := probe.NewVerifyingClient(guard, userAgent, false)
	code, _, ok := client.PostJSONBody(webhook, string(body), 1<<20)
	if !ok || code >= 300 {
		return fmt.Errorf("webhook POST to %s failed (status %d)", safe, code)
	}
	fmt.Printf("\nwebhook: POST %s -> %d\n", safe, code)
	return nil
}
