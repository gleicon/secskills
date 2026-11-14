package exposure

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/probe"
)

// inventoryHostLimit bounds the per-host table so a /20 stays readable.
const inventoryHostLimit = 50

// InventoryCounts returns the number of hosts and open services observed in a
// block workdir (0, 0 for an app target).
func InventoryCounts(wd string) (hosts, services int) {
	obs := loadInventory(wd)
	return len(hostPorts(obs)), len(obs)
}

func loadInventory(wd string) []Observation {
	path := filepath.Join(wd, "enriched-observations.jsonl")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(wd, "observations.jsonl")
	}
	obs, _ := probe.Load(path)
	return obs
}

// Inventory renders the network inventory of a block workdir as Markdown: host
// and service counts, open datastores, and a per-host port table. It returns ""
// when the workdir holds no network observations (an app target), so the
// report can include it unconditionally.
func Inventory(wd string) string {
	obs := loadInventory(wd)
	if len(obs) == 0 {
		return ""
	}
	hp := hostPorts(obs)
	ips := make([]string, 0, len(hp))
	for ip := range hp {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })

	tally := map[string]int{}
	var datastores []string
	for _, o := range obs {
		svc := o.Service
		if svc == "" {
			svc = "unknown"
		}
		tally[svc]++
		if DatastorePorts[o.Service] {
			datastores = append(datastores, fmt.Sprintf("`%s` %s", hostPort(o.IP, o.Port), o.Service))
		}
	}
	sort.Strings(datastores)

	var b strings.Builder
	fmt.Fprintf(&b, "%d hosts, %d open services. Services by type: %s.\n\n", len(ips), len(obs), svcTally(tally))
	if len(datastores) > 0 {
		fmt.Fprintf(&b, "Datastores reachable from the internet (%d) — these should not be exposed: %s.\n\n",
			len(datastores), strings.Join(datastores, ", "))
	}
	b.WriteString("| Host | Open services |\n|------|---------------|\n")
	for i, ip := range ips {
		if i == inventoryHostLimit {
			fmt.Fprintf(&b, "\n_(+%d more hosts in the workdir observations)_\n", len(ips)-inventoryHostLimit)
			break
		}
		var svcs []string
		for _, o := range hp[ip] {
			s := fmt.Sprintf("%d/%s", o.Port, orService(o.Service))
			if o.Product != "" {
				s += " " + strings.TrimSpace(o.Product+" "+o.Version)
			}
			svcs = append(svcs, mdEscape(s))
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", ip, strings.Join(svcs, ", "))
	}
	return b.String()
}

func orService(s string) string {
	if s == "" {
		return "tcp"
	}
	return s
}
