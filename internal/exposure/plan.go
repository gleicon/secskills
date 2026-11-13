package exposure

import (
	"fmt"
	"math"
	"net"
	"os"
	"sort"
)

// Shard is one worker's share of a sweep plan.
type Shard struct {
	Prefixes []string `json:"-"`
	IPs      float64  `json:"-"`
}

// ShardPrefixes distributes prefixes across n bins to equalize address count
// (greedy longest-processing-time: sort by size descending, place each into the
// currently lightest bin). Empty bins are dropped so --shards larger than the
// prefix count does not emit empty shard files.
func ShardPrefixes(prefixes []string, n int) []Shard {
	type sized struct {
		cidr string
		ips  float64
	}
	items := make([]sized, 0, len(prefixes))
	for _, p := range prefixes {
		items = append(items, sized{p, prefixIPs(p)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ips > items[j].ips })

	if n > len(items) {
		n = len(items)
	}
	bins := make([]Shard, n)
	for _, it := range items {
		// find the lightest bin
		min := 0
		for i := 1; i < n; i++ {
			if bins[i].IPs < bins[min].IPs {
				min = i
			}
		}
		bins[min].Prefixes = append(bins[min].Prefixes, it.cidr)
		bins[min].IPs += it.ips
	}
	for i := range bins {
		sort.Strings(bins[i].Prefixes)
	}
	return bins
}

// prefixIPs is the address count of an IPv4 CIDR (2^host-bits).
func prefixIPs(cidr string) float64 {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := n.Mask.Size()
	return math.Pow(2, float64(bits-ones))
}

// WriteLines writes lines to path, one per line.
func WriteLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := fmt.Fprintln(f, l); err != nil {
			return err
		}
	}
	return nil
}
