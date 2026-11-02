package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Response-integrity baselines (AC-1, malicious LLM intermediaries).
// An intermediary that rewrites responses leaves a stable endpoint's bytes
// changed between runs. `secskills integrity snapshot <url>` records a sha256 of
// the bounded response body; `secskills integrity verify <url>` re-fetches and
// reports drift. Verification is a deliberate operator step, not a silent
// retest side effect: a POST-based chat surface cannot be re-verified with the
// GET that retest performs, so pretending it could would manufacture drift.

// integrityHashPrefix keeps the digest format in one place (baseline file,
// comparison, and messages all agree on it).
const integrityHashPrefix = "sha256:"

// integrityMaxBytes bounds the body a baseline covers.
const integrityMaxBytes = 32 * 1024

type integrityRecord struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Time   string `json:"time"`
}

// responseDigest fetches url (bounded GET) and returns its canonical digest and
// HTTP status. ok is false when the host is unreachable or blocked.
func responseDigest(url string) (digest string, code int, ok bool) {
	code, _, body, ok := getWithBody(url, integrityMaxBytes)
	if !ok {
		return "", 0, false
	}
	sum := sha256.Sum256([]byte(body))
	return integrityHashPrefix + fmt.Sprintf("%x", sum), code, true
}

// integrityBaseline records a 2xx baseline; anything else is not a stable
// response worth anchoring.
func integrityBaseline(url string) (string, error) {
	sum, code, ok := responseDigest(url)
	if !ok {
		return "", fmt.Errorf("unreachable: %s", url)
	}
	if code < 200 || code >= 300 {
		return "", fmt.Errorf("unexpected status %d (baselines require 2xx)", code)
	}
	return sum, nil
}

func loadIntegrityBaseline(store, url string) (integrityRecord, bool) {
	raw, err := os.ReadFile(store)
	if err != nil {
		return integrityRecord{}, false
	}
	var rec integrityRecord
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		var r integrityRecord
		if json.Unmarshal([]byte(line), &r) != nil || r.URL == "" {
			continue
		}
		if r.URL == url {
			rec, found = r, true // append-only: the last baseline wins
		}
	}
	return rec, found
}

func cmdIntegrity(args []string) error {
	fs := flag.NewFlagSet("integrity", flag.ContinueOnError)
	store := fs.String("store", "./integrity-baselines.jsonl", "append-only baseline ledger")
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	rest, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) < 2 {
		return fmt.Errorf("usage: secskills integrity [--store file] <snapshot|verify> <url> --confirm")
	}
	op, url := rest[0], rest[1]
	// Both operations send live traffic to the target: same gate as test.
	if err := gateNotice("integrity "+op, url, *confirm); err != nil {
		return err
	}
	switch op {
	case "snapshot":
		sum, err := integrityBaseline(url)
		if err != nil {
			return err
		}
		rec := integrityRecord{URL: url, SHA256: sum, Time: nowRFC()}
		if err := appendJSONL(*store, rec); err != nil {
			return fmt.Errorf("write baseline: %w", err)
		}
		fmt.Printf("baseline %s  %s -> %s\n", sum, url, *store)
		return nil
	case "verify":
		rec, ok := loadIntegrityBaseline(*store, url)
		if !ok {
			return fmt.Errorf("no baseline for %s in %s — snapshot first", url, *store)
		}
		sum, _, ok := responseDigest(url)
		if !ok {
			return fmt.Errorf("INCONCLUSIVE: unreachable: %s", url)
		}
		if sum == rec.SHA256 {
			fmt.Printf("OK: response matches integrity baseline (%s)\n", sum)
			return nil
		}
		return fmt.Errorf("DRIFT: baseline %s, observed %s — possible intermediary rewrite", rec.SHA256, sum)
	default:
		return fmt.Errorf("unknown integrity op %q (snapshot|verify)", op)
	}
}
