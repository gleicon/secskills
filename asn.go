package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ASN / CIDR inventory (spec N-1). An ASN resolves to its announced prefixes via
// RIPE Stat, falling back to IRR (whois -i origin) when RIPE is unreachable.
// Prefixes are cached with a TTL and diffed, so a re-run reports drift instead
// of re-fetching. Resolution is read-only OSINT and does not touch customer
// hosts; the authorization gate still applies before any prefix is scanned.

const asnPrefixTTL = 24 * time.Hour

// prefixCache is the on-disk record for one ASN's announced prefixes.
type prefixCache struct {
	ASN       string    `json:"asn"`
	Prefixes  []string  `json:"prefixes"`
	Source    string    `json:"source"` // ripe-stat | irr
	FetchedAt time.Time `json:"fetched_at"`
}

// normalizeASN accepts "AS64500", "as64500", or "64500" and returns the
// canonical "AS64500" form plus the bare number string.
func normalizeASN(s string) (canonical, number string, err error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, "AS")
	if t == "" || strings.IndexFunc(t, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return "", "", fmt.Errorf("invalid ASN %q (want AS64500 or 64500)", s)
	}
	return "AS" + t, t, nil
}

var ripePrefixRe = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$|^[0-9a-fA-F:]+/\d{1,3}$`)

// ripeAnnouncedPrefixes is the subset of the RIPE Stat announced-prefixes
// response we consume.
type ripeAnnouncedPrefixes struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

// parseRIPEPrefixes extracts the sorted, de-duplicated prefix list from a RIPE
// Stat announced-prefixes JSON body. Malformed entries are dropped, not fatal.
func parseRIPEPrefixes(body []byte) ([]string, error) {
	var r ripeAnnouncedPrefixes
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range r.Data.Prefixes {
		pfx := strings.TrimSpace(p.Prefix)
		if ripePrefixRe.MatchString(pfx) && !seen[pfx] {
			seen[pfx] = true
			out = append(out, pfx)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid prefixes in RIPE response")
	}
	return out, nil
}

// parseIRRPrefixes extracts route:/route6: prefixes from whois -i origin output.
func parseIRRPrefixes(whoisOut string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(whoisOut, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if key != "route" && key != "route6" {
			continue
		}
		pfx := strings.TrimSpace(v)
		if ripePrefixRe.MatchString(pfx) && !seen[pfx] {
			seen[pfx] = true
			out = append(out, pfx)
		}
	}
	sort.Strings(out)
	return out
}

// diffPrefixes returns prefixes added and removed going from old to cur.
func diffPrefixes(old, cur []string) (added, removed []string) {
	oset, cset := map[string]bool{}, map[string]bool{}
	for _, p := range old {
		oset[p] = true
	}
	for _, p := range cur {
		cset[p] = true
		if !oset[p] {
			added = append(added, p)
		}
	}
	for _, p := range old {
		if !cset[p] {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// asnPrefixCachePath is the cache file for an ASN's prefixes under the data dir.
func asnPrefixCachePath(dataDir, number string) string {
	return filepath.Join(dataDir, "asn-AS"+number+"-prefixes.json")
}

// loadPrefixCache reads a prefix cache if present and unexpired.
func loadPrefixCache(path string) (*prefixCache, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var c prefixCache
	if json.Unmarshal(b, &c) != nil {
		return nil, false
	}
	if time.Since(c.FetchedAt) > asnPrefixTTL {
		return &c, false // return stale data for diffing, but signal expiry
	}
	return &c, true
}

// resolveASNPrefixes returns an ASN's announced prefixes, using the unexpired
// cache when present, else RIPE Stat, else IRR. It writes the cache and prints
// any drift versus the previous cached set. Pure parsing is in parseRIPEPrefixes
// / parseIRRPrefixes so it is unit-tested without the network.
func resolveASNPrefixes(dataDir, asn string) ([]string, string, error) {
	canonical, number, err := normalizeASN(asn)
	if err != nil {
		return nil, "", err
	}
	path := asnPrefixCachePath(dataDir, number)
	prev, fresh := loadPrefixCache(path)
	if fresh {
		fmt.Printf("[asn] %s: %d prefixes (cache, fetched %s)\n", canonical, len(prev.Prefixes), prev.FetchedAt.Format("2006-01-02 15:04"))
		return prev.Prefixes, prev.Source, nil
	}

	prefixes, source := ripeFetchPrefixes(number)
	if len(prefixes) == 0 {
		prefixes, source = irrFetchPrefixes(canonical)
	}
	if len(prefixes) == 0 {
		if prev != nil {
			fmt.Fprintf(os.Stderr, "[asn] %s: resolution failed, using stale cache (%d prefixes)\n", canonical, len(prev.Prefixes))
			return prev.Prefixes, prev.Source + "-stale", nil
		}
		return nil, "", fmt.Errorf("could not resolve prefixes for %s (RIPE and IRR both failed)", canonical)
	}

	if prev != nil {
		if added, removed := diffPrefixes(prev.Prefixes, prefixes); len(added)+len(removed) > 0 {
			fmt.Printf("[asn] %s drift: +%d -%d prefixes since %s\n", canonical, len(added), len(removed), prev.FetchedAt.Format("2006-01-02"))
		}
	}
	os.MkdirAll(dataDir, 0o755)
	c := prefixCache{ASN: canonical, Prefixes: prefixes, Source: source, FetchedAt: time.Now().UTC()}
	if b, err := json.MarshalIndent(c, "", "  "); err == nil {
		os.WriteFile(path, b, 0o644)
	}
	fmt.Printf("[asn] %s: %d prefixes (%s)\n", canonical, len(prefixes), source)
	return prefixes, source, nil
}

// ripeFetchPrefixes queries RIPE Stat through the throttled fetch layer.
func ripeFetchPrefixes(number string) ([]string, string) {
	url := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + number
	body, err := httpDo("ripe-stat", "GET", url, "", 2)
	if err != nil {
		return nil, ""
	}
	pfx, err := parseRIPEPrefixes(body)
	if err != nil {
		return nil, ""
	}
	return pfx, "ripe-stat"
}

// irrFetchPrefixes falls back to IRR via whois -i origin when the whois tool is
// present. Returns nil when whois is absent or yields nothing.
func irrFetchPrefixes(canonical string) ([]string, string) {
	if !has("whois") {
		return nil, ""
	}
	out, err := exec.Command("whois", "-h", "whois.radb.net", "--", "-i origin "+canonical).Output()
	if err != nil {
		return nil, ""
	}
	pfx := parseIRRPrefixes(string(out))
	if len(pfx) == 0 {
		return nil, ""
	}
	return pfx, "irr"
}
