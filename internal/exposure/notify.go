package exposure

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/jsonl"
)

// Notifier (spec NFR-1 / AC-2): when a CVE enters KEV (or any vuln.updated
// event), the affected tenants must be told in < 1h p95 WITHOUT a re-scan. This
// is a pure join of the feed delta journal against already-stored candidates —
// no target traffic — so the latency is the join time, not a scan. AC-2 is the
// synthetic path: inject one KEV event with its timestamp and assert the
// notification lands inside the budget.
type Notification struct {
	Tenant     string   `json:"tenant"`
	CVE        string   `json:"cve"`
	Assets     []string `json:"assets"`
	EventAt    string   `json:"event_at"`
	DetectedAt string   `json:"detected_at"`
	LatencySec float64  `json:"latency_sec"`
}

// deltaEvent mirrors appendDelta's JSON line.
type DeltaEvent struct {
	Event string   `json:"event"`
	At    string   `json:"at"`
	Added []string `json:"added"`
}

// NotifyForCVEs joins the given CVEs (each with the event time it became urgent)
// against the stored candidates, scoped per tenant, and returns one notification
// per (tenant, cve) that has at least one affected asset. now is the detection
// time; latency is now - event time.
func NotifyForCVEs(tenants []Tenant, cands []intel.Candidate, eventAt map[string]time.Time, now time.Time) []Notification {
	var out []Notification
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
			out = append(out, Notification{
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

// LoadDeltas reads the feed delta journal (vuln.updated events).
func LoadDeltas() []DeltaEvent {
	var out []DeltaEvent
	b, err := os.ReadFile(filepath.Join(feedDir(), "deltas.jsonl"))
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var e DeltaEvent
		if jsonl.JSONUnmarshalLine(ln, &e) {
			out = append(out, e)
		}
	}
	return out
}
