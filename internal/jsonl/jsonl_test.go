package jsonl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendJSONLRoundTrip(t *testing.T) {
	type row struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}
	path := filepath.Join(t.TempDir(), "rows.jsonl")
	in := []row{{"203.0.113.1", 22}, {"203.0.113.2", 443}, {"line\nbreak", 1}}
	for _, r := range in {
		if err := AppendJSONL(path, r); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != len(in) {
		t.Fatalf("%d lines, want %d (an embedded newline must stay escaped)", len(lines), len(in))
	}
	for i, ln := range lines {
		var got row
		if !JSONUnmarshalLine(ln, &got) || got != in[i] {
			t.Errorf("line %d: %q -> %+v, want %+v", i, ln, got, in[i])
		}
	}
	if JSONUnmarshalLine("{not json", &row{}) {
		t.Error("JSONUnmarshalLine accepted invalid JSON")
	}
}

func TestAppendJSONLUnmarshalableValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.jsonl")
	if err := AppendJSONL(path, make(chan int)); err == nil {
		t.Error("want error for unmarshalable value")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("file created for a failed write")
	}
}
