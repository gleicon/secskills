package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Feed ingest (spec FR-3): incremental, idempotent ingest of free intelligence
// sources. A source is fetched through the throttled httpDo layer, parsed with
// encoding/json (never by hand), stored, and diffed against the last cache so a
// vuln.updated event fires only when content actually changed. These are OSINT
// endpoints (CISA / FIRST) — no customer host is touched, so no gate applies.

// feedDir is the on-disk home for cached feeds and the delta journal.
func feedDir() string {
	if d := os.Getenv("SECSKILLS_FEED"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secskills", "feed")
}

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVEntry is one CISA Known-Exploited-Vulnerabilities record (the subset we use).
type KEVEntry struct {
	CVE             string `json:"cveID"`
	Vendor          string `json:"vendorProject"`
	Product         string `json:"product"`
	Name            string `json:"vulnerabilityName"`
	DateAdded       string `json:"dateAdded"`
	DueDate         string `json:"dueDate"`
	KnownRansomware string `json:"knownRansomwareCampaignUse"`
}

type kevCatalog struct {
	CatalogVersion  string     `json:"catalogVersion"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// parseKEV extracts the KEV entries from the catalog JSON, sorted by CVE. Pure,
// so it is unit-tested without the network.
func parseKEV(body []byte) ([]KEVEntry, error) {
	var c kevCatalog
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, err
	}
	if len(c.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("KEV catalog has no vulnerabilities")
	}
	out := c.Vulnerabilities
	sort.Slice(out, func(i, j int) bool { return out[i].CVE < out[j].CVE })
	return out, nil
}

// kevSet returns the CVE ids as a set, for delta computation.
func kevSet(entries []KEVEntry) map[string]bool {
	s := make(map[string]bool, len(entries))
	for _, e := range entries {
		s[e.CVE] = true
	}
	return s
}

// EPSSScore is one FIRST EPSS probability record.
type EPSSScore struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
}

type epssResponse struct {
	Data []EPSSScore `json:"data"`
}

// parseEPSS extracts EPSS scores from the FIRST API JSON response.
func parseEPSS(body []byte) ([]EPSSScore, error) {
	var r epssResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return r.Data, nil
}

// appendDelta records a vuln.updated event (one JSON line) — the signal that a
// downstream notifier joins against tenant assets.
func appendDelta(source string, added []string) error {
	if len(added) == 0 {
		return nil
	}
	ev := map[string]any{
		"event": "vuln.updated", "source": source, "at": nowRFC(), "added": added, "count": len(added),
	}
	return appendJSONL(filepath.Join(feedDir(), "deltas.jsonl"), ev)
}

func cmdFeed(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills feed <kev|epss> ...")
	}
	switch args[0] {
	case "kev":
		return feedKEV(args[1:])
	case "epss":
		return feedEPSS(args[1:])
	default:
		return fmt.Errorf("unknown feed source %q (want kev|epss)", args[0])
	}
}

// feedKEV ingests the CISA KEV catalog, caches it, and reports the delta since
// the last run (newly-added exploited CVEs — the reprioritisation signal).
func feedKEV(args []string) error {
	fs := flag.NewFlagSet("feed kev", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := httpDo("cisa-kev", "GET", kevURL, "", 2)
	if err != nil {
		return fmt.Errorf("fetch KEV: %w", err)
	}
	entries, err := parseKEV(body)
	if err != nil {
		return err
	}

	dir := feedDir()
	os.MkdirAll(dir, 0o755)
	cachePath := filepath.Join(dir, "kev.json")

	var prev []KEVEntry
	if b, err := os.ReadFile(cachePath); err == nil {
		json.Unmarshal(b, &prev)
	}
	prevSet, curSet := kevSet(prev), kevSet(entries)
	var added, removed []string
	for cve := range curSet {
		if !prevSet[cve] {
			added = append(added, cve)
		}
	}
	for cve := range prevSet {
		if !curSet[cve] {
			removed = append(removed, cve)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)

	// FR-3: persist only when content changed (idempotent re-runs are cheap).
	if len(added) == 0 && len(removed) == 0 && len(prev) == len(entries) {
		fmt.Printf("[kev] %d entries (unchanged)\n", len(entries))
		return nil
	}
	b, _ := json.MarshalIndent(entries, "", "  ")
	if err := os.WriteFile(cachePath, b, 0o644); err != nil {
		return err
	}
	if err := appendDelta("cisa-kev", added); err != nil {
		return err
	}
	fmt.Printf("[kev] %d entries (+%d new, -%d removed) -> %s\n", len(entries), len(added), len(removed), cachePath)
	for _, cve := range added {
		fmt.Printf("  NEW KEV %s\n", cve)
	}
	return nil
}

// feedEPSS looks up EPSS probabilities for the given CVEs through the FIRST API
// and prints them highest-first. EPSS is the per-CVE exploit-probability signal
// that weights the score without a scan.
func feedEPSS(args []string) error {
	fs := flag.NewFlagSet("feed epss", flag.ContinueOnError)
	cves := fs.String("cve", "", "comma-separated CVE ids to look up")
	if err := fs.Parse(args); err != nil {
		return err
	}
	list := splitCSV(*cves)
	if len(list) == 0 {
		return fmt.Errorf("usage: secskills feed epss --cve CVE-2026-1234,CVE-2026-5678")
	}
	url := "https://api.first.org/data/v1/epss?cve=" + strings.Join(list, ",")
	body, err := httpDo("first-epss", "GET", url, "", 2)
	if err != nil {
		return fmt.Errorf("fetch EPSS: %w", err)
	}
	scores, err := parseEPSS(body)
	if err != nil {
		return err
	}
	sort.Slice(scores, func(i, j int) bool { return scores[i].EPSS > scores[j].EPSS })
	if len(scores) == 0 {
		fmt.Println("[epss] no scores (CVEs unknown to EPSS)")
		return nil
	}
	for _, s := range scores {
		fmt.Printf("  %-18s epss=%s percentile=%s\n", s.CVE, s.EPSS, s.Percentile)
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
