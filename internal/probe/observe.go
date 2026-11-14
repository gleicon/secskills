package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ObservationFingerprintVersion is bumped whenever the set of fields that
// define an observation's identity changes, so cached rows from an older schema
// never silently collide with new ones. It is part of the content hash.
const ObservationFingerprintVersion = 1

// Observation is one externally-observed fact about a reachable (ip, port): the
// service, product/version, CPE, and optional TLS metadata derived without authentication
// or state change. It is the v0 cache unit and the first non-finding output
// type (spec N-2). Rows are append-only, sourced, and timestamped; Fingerprint
// gives each one a stable content address so the store can dedupe.
type Observation struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"` // ssh, http, https, tls, ...
	Product string `json:"product,omitempty"` // OpenSSH, nginx, ...
	Version string `json:"version,omitempty"`
	CPE     string `json:"cpe,omitempty"`
	Banner  string `json:"banner,omitempty"`

	TLS *TLSInfo `json:"tls,omitempty"`

	// Provenance. Source names the tool/method (naabu, httpx, native-connect,
	// internetdb). Confidence is low|medium|high|verified, matching the detection
	// ladder (L0..L3). ASN/Prefix attach the inventory context when known.
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	ASN        int    `json:"asn,omitempty"`
	Prefix     string `json:"prefix,omitempty"`

	ObservedAt         string `json:"observed_at"`           // RFC3339 UTC
	FingerprintVersion int    `json:"fingerprint_version"`   // == ObservationFingerprintVersion
	Fingerprint        string `json:"fingerprint,omitempty"` // content address; set by Normalize/Fingerprint
}

// TLSInfo is the minimal externally-visible TLS metadata.
type TLSInfo struct {
	Subject    string   `json:"subject,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
	MinVersion string   `json:"min_version,omitempty"` // tls1.0 .. tls1.3
	SANs       []string `json:"sans,omitempty"`
}

// ContentHash is the content address of an observation's identity: the fields
// that make two observations "the same fact". Timestamp, banner text, and
// provenance are deliberately excluded so a re-observation of an unchanged
// service dedupes to one identity across runs.
func (o Observation) ContentHash() string {
	var b strings.Builder
	fmt.Fprintf(&b, "v%d|%s|%d|%s|%s|%s|%s",
		ObservationFingerprintVersion, o.IP, o.Port, o.Service, o.Product, o.Version, o.CPE)
	if o.TLS != nil {
		sans := append([]string(nil), o.TLS.SANs...)
		sort.Strings(sans)
		fmt.Fprintf(&b, "|%s|%s|%s", o.TLS.Issuer, o.TLS.MinVersion, strings.Join(sans, ","))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Normalize fills FingerprintVersion, Fingerprint, and ObservedAt (if unset),
// returning the completed row ready to store. Call it before Store.Append.
func (o Observation) Normalize() Observation {
	o.FingerprintVersion = ObservationFingerprintVersion
	if o.ObservedAt == "" {
		o.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	}
	o.Fingerprint = o.ContentHash() // identity excludes ObservedAt, so order is safe
	return o
}

// Store is an append-only JSONL sink for observations. One row per line keeps
// the corpus streamable and recoverable after a mid-sweep kill (spec AC-7): a
// partially written final line is the only loss, and it is detectable.
type Store struct {
	Path string
}

// Append normalizes and writes one observation as a JSON line. It is safe for
// concurrent single-process callers only through the OS append guarantee for
// small writes; a worker fleet should shard by Path.
func (s Store) Append(o Observation) error {
	o = o.Normalize()
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Load reads every well-formed observation from the store, skipping a trailing
// partial line (the resumable-sweep guarantee). A malformed interior line is a
// hard error — that is corruption, not an interrupted write.
func Load(path string) ([]Observation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	out := make([]Observation, 0, len(lines))
	for i, ln := range lines {
		if ln == "" {
			continue
		}
		var o Observation
		if err := json.Unmarshal([]byte(ln), &o); err != nil {
			// A broken last line is an interrupted append, not corruption.
			if i == len(lines)-1 {
				break
			}
			return nil, fmt.Errorf("observation store %s line %d: %w", path, i+1, err)
		}
		out = append(out, o)
	}
	return out, nil
}
