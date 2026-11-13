package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/finding"
)

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
	tenants, err := exposure.LoadTenants(*tenantsPath)
	if err != nil {
		return fmt.Errorf("tenants: %w", err)
	}
	t, ok := exposure.FindTenant(tenants, *tenantID)
	if !ok {
		return fmt.Errorf("no tenant %q in %s", *tenantID, *tenantsPath)
	}
	cands := exposure.LoadCandidates(filepath.Join(*wd, "candidates.jsonl"))
	feed := exposure.BuildTenantFeed(t, cands, finding.NowRFC())

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
	fmt.Print(exposure.RenderTenantBrief(feed))

	if *webhook != "" {
		if err := exposure.PostWebhook(*webhook, b); err != nil {
			return err
		}
	}
	return nil
}
