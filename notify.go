package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/intel"
)

// Notifier (spec NFR-1 / AC-2): when a CVE enters KEV (or any vuln.updated
// event), the affected tenants must be told in < 1h p95 WITHOUT a re-scan. This
// is a pure join of the feed delta journal against already-stored candidates —
// no target traffic — so the latency is the join time, not a scan. AC-2 is the
// synthetic path: inject one KEV event with its timestamp and assert the
// notification lands inside the budget.
type notification struct {
	Tenant     string   `json:"tenant"`
	CVE        string   `json:"cve"`
	Assets     []string `json:"assets"`
	EventAt    string   `json:"event_at"`
	DetectedAt string   `json:"detected_at"`
	LatencySec float64  `json:"latency_sec"`
}

// deltaEvent mirrors appendDelta's JSON line.
type deltaEvent struct {
	Event string   `json:"event"`
	At    string   `json:"at"`
	Added []string `json:"added"`
}

// notifyForCVEs joins the given CVEs (each with the event time it became urgent)
// against the stored candidates, scoped per tenant, and returns one notification
// per (tenant, cve) that has at least one affected asset. now is the detection
// time; latency is now - event time.
func notifyForCVEs(tenants []Tenant, cands []intel.Candidate, eventAt map[string]time.Time, now time.Time) []notification {
	var out []notification
	for _, t := range tenants {
		scoped := tenantFilter(cands, t)
		byCVE := map[string][]string{}
		for _, c := range scoped {
			byCVE[c.CVE] = append(byCVE[c.CVE], c.AssetIP)
		}
		for cve, ev := range eventAt {
			assets := byCVE[cve]
			if len(assets) == 0 {
				continue
			}
			sort.Strings(assets)
			out = append(out, notification{
				Tenant: t.Tenant, CVE: cve, Assets: assets,
				EventAt: ev.UTC().Format(time.RFC3339), DetectedAt: now.UTC().Format(time.RFC3339),
				LatencySec: now.Sub(ev).Seconds(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].CVE < out[j].CVE
	})
	return out
}

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
	tenants, err := loadTenants(*tenantsPath)
	if err != nil {
		return fmt.Errorf("tenants: %w", err)
	}
	cands := loadCandidates(filepath.Join(*wd, "candidates.jsonl"))
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
		for _, e := range loadDeltas() {
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

	notes := notifyForCVEs(tenants, cands, eventAt, now)
	outPath := filepath.Join(*wd, "notifications.jsonl")
	os.Remove(outPath)
	worst := 0.0
	for _, n := range notes {
		appendJSONL(outPath, n)
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

func loadDeltas() []deltaEvent {
	var out []deltaEvent
	b, err := os.ReadFile(filepath.Join(feedDir(), "deltas.jsonl"))
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var e deltaEvent
		if jsonUnmarshalLine(ln, &e) {
			out = append(out, e)
		}
	}
	return out
}
