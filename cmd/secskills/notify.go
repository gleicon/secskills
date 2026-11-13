package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/jsonl"
)

func cmdNotify(args []string) error {
	fs := flag.NewFlagSet("notify", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with candidates.jsonl")
	tenantsPath := fs.String("tenants", "", "tenants file (JSON array)")
	kevEvent := fs.String("kev-event", "", "synthetic: a single CVE id that just entered KEV (AC-2)")
	eventAtStr := fs.String("event-at", "", "synthetic: RFC3339 time the event fired (default: now)")
	budget := fs.Duration("budget", time.Hour, "max event->notify latency to PASS (NFR-1 = 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" || *tenantsPath == "" {
		return fmt.Errorf("usage: secskills notify --workdir <dir> --tenants <file> [--kev-event CVE --event-at TS]")
	}
	tenants, err := exposure.LoadTenants(*tenantsPath)
	if err != nil {
		return fmt.Errorf("tenants: %w", err)
	}
	cands := exposure.LoadCandidates(filepath.Join(*wd, "candidates.jsonl"))
	now := time.Now()

	eventAt := map[string]time.Time{}
	if *kevEvent != "" {
		ev := now
		if *eventAtStr != "" {
			ev, err = time.Parse(time.RFC3339, *eventAtStr)
			if err != nil {
				return fmt.Errorf("--event-at: %w", err)
			}
		}
		eventAt[*kevEvent] = ev
	} else {
		// Journal mode: every CVE from every vuln.updated event, stamped with
		// the event time, so the latency reflects the real reprioritisation.
		for _, e := range exposure.LoadDeltas() {
			ts, perr := time.Parse(time.RFC3339, e.At)
			if perr != nil {
				ts = now
			}
			for _, cve := range e.Added {
				if _, ok := eventAt[cve]; !ok {
					eventAt[cve] = ts
				}
			}
		}
		if len(eventAt) == 0 {
			fmt.Println("no vuln.updated events in the journal — run `secskills feed kev` first")
			return nil
		}
	}

	notes := exposure.NotifyForCVEs(tenants, cands, eventAt, now)
	outPath := filepath.Join(*wd, "notifications.jsonl")
	os.Remove(outPath)
	worst := 0.0
	for _, n := range notes {
		jsonl.AppendJSONL(outPath, n)
		if n.LatencySec > worst {
			worst = n.LatencySec
		}
		fmt.Printf("NOTIFY %-10s %-16s %d asset(s)  latency %.1fs\n", n.Tenant, n.CVE, len(n.Assets), n.LatencySec)
	}
	fmt.Printf("%d notification(s) -> %s\n", len(notes), outPath)

	if len(notes) > 0 && worst > budget.Seconds() {
		fmt.Printf("VERDICT: FAIL — worst latency %.0fs > budget %s (NFR-1).\n", worst, *budget)
		os.Exit(1)
	}
	if len(notes) > 0 {
		fmt.Printf("VERDICT: PASS — worst latency %.0fs within %s, no scan on the path (NFR-1/AC-2).\n", worst, *budget)
	}
	return nil
}
