package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
)

// cmdPlan turns an ASN (or an explicit prefix list) into a sharded capture plan:
// one slice of prefixes per VM, balanced by address count so every worker does
// roughly equal work. It is read-only OSINT — it resolves and distributes
// prefixes, it does NOT scan. The output (plan.json + shard-<i>.txt files) feeds
// deploy/capture.sh in PREFIXES mode: each VM captures its slice into its own
// append-only workdir, and every VM shares one read-only feed cache, so the
// feeds are paid for once, not once per VM.
func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	asn := fs.String("asn", "", "ASN to resolve (e.g. AS64500)")
	shards := fs.Int("shards", 1, "number of VMs / workers to split across")
	out := fs.String("out", "./plan", "output directory for plan.json + shard-<i>.txt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *asn == "" {
		return fmt.Errorf("usage: secskills plan --asn AS64500 --shards N [--out dir]")
	}
	if *shards < 1 {
		return fmt.Errorf("--shards must be >= 1")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}

	dataDir := filepath.Join(*out, "data")
	prefixes, source, err := resolveASNPrefixes(dataDir, *asn)
	if err != nil {
		return err
	}
	// IPv4 only for the sweep; IPv6 prefixes are too large to enumerate and are
	// refused by expandCIDR, so leave them out of the capture plan.
	var v4 []string
	for _, p := range prefixes {
		if ip, _, err := net.ParseCIDR(p); err == nil && ip.To4() != nil {
			v4 = append(v4, p)
		}
	}
	if len(v4) == 0 {
		return fmt.Errorf("no IPv4 prefixes to plan for %s", *asn)
	}

	plan := shardPrefixes(v4, *shards)

	manifest := map[string]any{
		"asn":      *asn,
		"source":   source,
		"prefixes": len(v4),
		"shards":   len(plan),
	}
	shardMeta := make([]map[string]any, 0, len(plan))
	total := 0.0
	for i, s := range plan {
		name := fmt.Sprintf("shard-%d.txt", i)
		if err := writeLines(filepath.Join(*out, name), s.prefixes); err != nil {
			return err
		}
		shardMeta = append(shardMeta, map[string]any{
			"vm":         i,
			"file":       name,
			"prefixes":   len(s.prefixes),
			"approx_ips": int64(s.ips),
		})
		total += s.ips
	}
	manifest["approx_ips"] = int64(total)
	manifest["shard_detail"] = shardMeta
	b, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(filepath.Join(*out, "plan.json"), b, 0o644)

	fmt.Printf("plan: %s (%s) — %d IPv4 prefixes, ~%d addresses, %d shards -> %s\n",
		*asn, source, len(v4), int64(total), len(plan), *out)
	for i, s := range plan {
		fmt.Printf("  shard-%d.txt  %3d prefixes  ~%d addrs\n", i, len(s.prefixes), int64(s.ips))
	}
	fmt.Printf("\nper VM (one shared feed cache, no per-VM feed download):\n")
	fmt.Printf("  SECSKILLS_FEED=/mnt/feed PREFIXES=%s/shard-<i>.txt CONFIRM=yes ./capture.sh\n", *out)
	return nil
}

type shard struct {
	prefixes []string
	ips      float64
}

// shardPrefixes distributes prefixes across n bins to equalize address count
// (greedy longest-processing-time: sort by size descending, place each into the
// currently lightest bin). Empty bins are dropped so --shards larger than the
// prefix count does not emit empty shard files.
func shardPrefixes(prefixes []string, n int) []shard {
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
	bins := make([]shard, n)
	for _, it := range items {
		// find the lightest bin
		min := 0
		for i := 1; i < n; i++ {
			if bins[i].ips < bins[min].ips {
				min = i
			}
		}
		bins[min].prefixes = append(bins[min].prefixes, it.cidr)
		bins[min].ips += it.ips
	}
	for i := range bins {
		sort.Strings(bins[i].prefixes)
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

func writeLines(path string, lines []string) error {
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
