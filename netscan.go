package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gleicon/secskills/internal/probe"
)

// Rate-gated host enumeration for ASN/CIDR mode (spec N-1). A block is expanded
// to host IPs under a /20 cap (override with --allow-large), then each IP is
// connect-scanned for a small set of common ports through the shared rate gate.
// Reachable (ip, port) pairs become probe.Observation rows — the v0 cache unit —
// never destructive: a TCP connect, immediately closed, no payload.

// maxCIDRHosts caps a single block at a /20 (4096 addresses) unless the operator
// passes --allow-large. A larger sweep is a deliberate, logged decision.
const maxCIDRHosts = 1 << 12 // /20

// defaultScanPorts is the cheap triage set: the ports that most often reveal a
// product/version from a banner. Raw IP reachability, not an HTTP assumption.
var defaultScanPorts = []int{22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017}

// cidrHostCount returns the number of addresses in a prefix, saturating at a
// large sentinel for very wide blocks so the caller can reject before expanding.
func cidrHostCount(cidr string) (int, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}
	ones, bits := n.Mask.Size()
	hostBits := bits - ones
	if hostBits >= 31 { // would overflow int on 32-bit; far past any cap anyway
		return 1 << 30, nil
	}
	return 1 << hostBits, nil
}

// expandCIDR returns every address in a prefix, refusing a block larger than the
// cap unless allowLarge is set. IPv6 blocks are always refused for enumeration
// (astronomically large); they are recorded as inventory but not swept.
func expandCIDR(cidr string, allowLarge bool) ([]net.IP, error) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("%s is IPv6 — recorded as inventory, not enumerated", cidr)
	}
	count, _ := cidrHostCount(cidr)
	if count > maxCIDRHosts && !allowLarge {
		return nil, fmt.Errorf("%s has %d addresses (> /20 cap of %d) — pass --allow-large to override", cidr, count, maxCIDRHosts)
	}
	var out []net.IP
	for cur := n.IP.Mask(n.Mask); n.Contains(cur); cur = nextIP(cur) {
		c := make(net.IP, len(cur))
		copy(c, cur)
		out = append(out, c)
	}
	return out, nil
}

// nextIP returns the address one greater than ip (big-endian increment).
func nextIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// connectScan runs a rate-gated TCP connect scan of ips × ports and returns one
// Observation per reachable pair. tick gates every dial so a whole-block sweep
// respects the global rate (NFR-2); a nil tick runs unthrottled (tests). asn and
// prefix are stamped onto every observation for inventory context.
//
// Each hit is streamed to sink (if non-nil) the moment it is found, so a sweep
// killed mid-prefix keeps every observation already made — the resumable-sweep
// guarantee (AC-7). A sink error stops that worker but not the scan; the
// returned slice is the authoritative in-memory result regardless.
func connectScan(ips []net.IP, ports []int, asnNum int, prefix string, tick <-chan time.Time, workers int, sink func(probe.Observation) error) []probe.Observation {
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var obs []probe.Observation
	var wg sync.WaitGroup
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if tick != nil {
					<-tick
				}
				addr := net.JoinHostPort(j.ip, fmt.Sprint(j.port))
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					continue
				}
				conn.Close()
				o := probe.Observation{
					IP: j.ip, Port: j.port,
					Service:    serviceForPort(j.port),
					Source:     "native-connect",
					Confidence: "medium", // L1: reachability confirmed, product not yet
					ASN:        asnNum,
					Prefix:     prefix,
				}
				mu.Lock()
				obs = append(obs, o)
				if sink != nil {
					_ = sink(o)
				}
				mu.Unlock()
			}
		}()
	}
	for _, ip := range ips {
		for _, p := range ports {
			jobs <- job{ip.String(), p}
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(obs, func(i, j int) bool {
		if obs[i].IP != obs[j].IP {
			return obs[i].IP < obs[j].IP
		}
		return obs[i].Port < obs[j].Port
	})
	return obs
}

// serviceForPort labels the common ports; unknown ports get an empty service,
// which the later banner stage may fill.
func serviceForPort(p int) string {
	switch p {
	case 22:
		return "ssh"
	case 25, 465, 587:
		return "smtp"
	case 80, 8080:
		return "http"
	case 443, 8443:
		return "https"
	case 110, 995:
		return "pop3"
	case 143, 993:
		return "imap"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 9200:
		return "elasticsearch"
	case 27017:
		return "mongodb"
	}
	return ""
}

// discoverBlock is the ASN/CIDR discovery entry point (spec N-1). It resolves an
// ASN to prefixes (or takes a single CIDR), enforces the gate and the /20 cap
// per prefix, runs a rate-gated connect scan, and persists observations plus an
// HTTP-port live_hosts.json for the downstream `test` path. Observations are the
// durable artifact; the scan is throwaway.
func discoverBlock(asn, cidr string, allowLarge, confirm bool, workers int) error {
	label := cidr
	asnNum := 0
	var prefixes []string
	if asn != "" {
		canonical, number, err := normalizeASN(asn)
		if err != nil {
			return err
		}
		label = canonical
		fmt.Sscanf(number, "%d", &asnNum)
	}
	wd := workdir(label)
	dataDir := filepath.Join(wd, "data")
	fmt.Printf("== discover block: %s (workdir %s) ==\n", label, wd)

	if asn != "" {
		pfx, _, err := resolveASNPrefixes(dataDir, asn)
		if err != nil {
			return err
		}
		prefixes = pfx
	} else {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid --cidr %q: %w", cidr, err)
		}
		prefixes = []string{cidr}
	}

	tick := rateGate()
	defer tick.Stop()
	store := probe.Store{Path: filepath.Join(wd, "observations.jsonl")}
	// Authorization is decided per IP, not per prefix: authorizing a prefix's
	// network address must never authorize addresses the scope does not cover,
	// and out_of_scope is honored for every address even under --confirm.
	allow := scopeIPFilter(confirm)
	var allObs []probe.Observation
	for _, pfx := range prefixes {
		// Fast-fail with the authorization notice when nothing in this prefix
		// could be in scope; the per-IP filter below is the real enforcement.
		netIP, _, _ := net.ParseCIDR(pfx)
		if err := gateNotice("discover", netIP.String(), confirm); err != nil {
			return err
		}
		expanded, err := expandCIDR(pfx, allowLarge)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[scan] skip %s: %v\n", pfx, err)
			continue
		}
		ips := make([]net.IP, 0, len(expanded))
		for _, ip := range expanded {
			if allow(ip) {
				ips = append(ips, ip)
			}
		}
		if dropped := len(expanded) - len(ips); dropped > 0 {
			fmt.Printf("[scope] %s: %d/%d addresses out of scope, not scanned\n", pfx, dropped, len(expanded))
		}
		// Stream each hit to the store as it is found (AC-7): a kill mid-prefix
		// keeps every observation already written.
		var storeErr error
		obs := connectScan(ips, defaultScanPorts, asnNum, pfx, tick.C, workers, func(o probe.Observation) error {
			if err := store.Append(o); err != nil {
				storeErr = err
				return err
			}
			return nil
		})
		if storeErr != nil {
			return fmt.Errorf("observation store: %w", storeErr)
		}
		allObs = append(allObs, obs...)
		fmt.Printf("[scan] %s: %d IPs, %d reachable services\n", pfx, len(ips), len(obs))
	}

	var lives []LiveHost
	for _, o := range allObs {
		if o.Service == "http" || o.Service == "https" {
			scheme := "http"
			if o.Service == "https" {
				scheme = "https"
			}
			lives = append(lives, LiveHost{
				URL:    fmt.Sprintf("%s://%s:%d", scheme, o.IP, o.Port),
				Status: 0, IP: o.IP, Prefix: o.Prefix, ASN: o.ASN,
			})
		}
	}
	b, _ := json.MarshalIndent(lives, "", "  ")
	os.WriteFile(filepath.Join(wd, "live_hosts.json"), b, 0o644)
	fmt.Printf("[store] %d observations -> %s/observations.jsonl ; %d HTTP services -> live_hosts.json\n", len(allObs), wd, len(lives))
	fmt.Printf("\nNext: secskills test <ip> --confirm  (per in-scope host)\n")
	return nil
}
