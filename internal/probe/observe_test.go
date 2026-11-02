package probe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContentHashStableAcrossReobservation(t *testing.T) {
	a := Observation{IP: "203.0.113.17", Port: 443, Service: "https", Product: "nginx", Version: "1.25.3",
		Source: "httpx", Confidence: "medium", ObservedAt: "2026-11-02T09:00:00Z"}
	b := a                                  // same fact, later run
	b.ObservedAt = "2026-11-02T18:00:00Z"   // time differs
	b.Banner = "Server: nginx"              // volatile text differs
	b.Source, b.Confidence = "naabu", "low" // provenance differs
	if a.ContentHash() != b.ContentHash() {
		t.Fatalf("re-observation of an unchanged service must dedupe to one identity")
	}
}

func TestContentHashSeparatesVersions(t *testing.T) {
	a := Observation{IP: "203.0.113.17", Port: 443, Product: "nginx", Version: "1.25.3"}
	b := Observation{IP: "203.0.113.17", Port: 443, Product: "nginx", Version: "1.27.0"}
	if a.ContentHash() == b.ContentHash() {
		t.Fatalf("different version must be a different observation identity")
	}
}

func TestStoreAppendLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs.jsonl")
	s := Store{Path: path}
	in := Observation{IP: "203.0.113.44", Port: 22, Service: "ssh", Product: "OpenSSH", Version: "8.9p1",
		Source: "naabu", Confidence: "medium"}
	if err := s.Append(in); err != nil {
		t.Fatal(err)
	}
	rows, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].Fingerprint == "" || rows[0].FingerprintVersion != ObservationFingerprintVersion {
		t.Fatalf("Append must normalize fingerprint fields: %+v", rows[0])
	}
	if rows[0].ObservedAt == "" {
		t.Fatalf("Append must stamp ObservedAt")
	}
}

func TestLoadSkipsInterruptedFinalLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs.jsonl")
	good := `{"ip":"203.0.113.1","port":80,"source":"x","confidence":"low","observed_at":"2026-11-02T00:00:00Z","fingerprint_version":1}` + "\n"
	partial := `{"ip":"203.0.113.2","port":4` // killed mid-write, no newline
	if err := os.WriteFile(path, []byte(good+partial), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := Load(path)
	if err != nil {
		t.Fatalf("a partial final line is an interrupted append, not an error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 complete row, got %d", len(rows))
	}
}

func TestLoadRejectsInteriorCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs.jsonl")
	body := "{bad json}\n" + `{"ip":"203.0.113.1","port":80}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatalf("a broken interior line is corruption and must error")
	}
}
