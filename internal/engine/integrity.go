package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gleicon/secskills/internal/fetch"
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

// IntegrityRecord is one response baseline: URL, body hash and time.
type IntegrityRecord struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Time   string `json:"time"`
}

// ResponseDigest fetches url (bounded GET) and returns its canonical digest and
// HTTP status. ok is false when the host is unreachable or blocked.
func ResponseDigest(url string) (digest string, code int, ok bool) {
	code, _, body, ok := fetch.GetWithBody(url, integrityMaxBytes)
	if !ok {
		return "", 0, false
	}
	sum := sha256.Sum256([]byte(body))
	return integrityHashPrefix + fmt.Sprintf("%x", sum), code, true
}

// IntegrityBaseline records a 2xx baseline; anything else is not a stable
// response worth anchoring.
func IntegrityBaseline(url string) (string, error) {
	sum, code, ok := ResponseDigest(url)
	if !ok {
		return "", fmt.Errorf("unreachable: %s", url)
	}
	if code < 200 || code >= 300 {
		return "", fmt.Errorf("unexpected status %d (baselines require 2xx)", code)
	}
	return sum, nil
}

// LoadIntegrityBaseline returns the latest baseline for url in the store.
func LoadIntegrityBaseline(store, url string) (IntegrityRecord, bool) {
	raw, err := os.ReadFile(store)
	if err != nil {
		return IntegrityRecord{}, false
	}
	var rec IntegrityRecord
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		var r IntegrityRecord
		if json.Unmarshal([]byte(line), &r) != nil || r.URL == "" {
			continue
		}
		if r.URL == url {
			rec, found = r, true // append-only: the last baseline wins
		}
	}
	return rec, found
}
