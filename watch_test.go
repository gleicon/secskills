package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestWatchDrift proves posture-drift classification by stable finding_key:
// a key present only in cur = NEW, only in prev = FIXED, in both = PERSISTING.
func TestWatchDrift(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	target := "drift.example"
	dir := storeDir(target)
	os.MkdirAll(dir, 0o755)
	write := func(name, id string, keys map[string]string) {
		var fs []Finding
		for k, sev := range keys {
			fs = append(fs, Finding{Key: k, Severity: sev})
		}
		r := Run{RunID: id, Findings: fs}
		b, _ := json.Marshal(r)
		os.WriteFile(filepath.Join(dir, name), b, 0o644)
	}
	// run-1: keys a,b ; run-2: keys b,c  => NEW=c, FIXED=a, PERSISTING=b
	write("run-1.json", "r1", map[string]string{"a": "HIGH", "b": "LOW"})
	write("run-2.json", "r2", map[string]string{"b": "LOW", "c": "MEDIUM"})
	d := computeDrift(target)
	if d == nil {
		t.Fatal("expected a drift entry")
	}
	if d.Counts["NEW"] != 1 || d.Counts["FIXED"] != 1 || d.Counts["PERSISTING"] != 1 {
		t.Errorf("drift counts wrong: %+v", d.Counts)
	}
}
