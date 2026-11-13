package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gleicon/secskills/internal/netsec"
)

func TestIntegritySnapshotVerifyDrift(t *testing.T) {
	netsec.AllowLocalProbes = true
	defer func() { netsec.AllowLocalProbes = false }()
	body := "stable-content"
	sv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer sv.Close()
	store := t.TempDir() + "/bl.jsonl"
	if err := cmdIntegrity([]string{"--confirm", "--store", store, "snapshot", sv.URL}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := cmdIntegrity([]string{"--confirm", "--store", store, "verify", sv.URL}); err != nil {
		t.Fatalf("verify after snapshot: %v", err)
	}
	body = "tampered-content"
	if err := cmdIntegrity([]string{"--confirm", "--store", store, "verify", sv.URL}); err == nil {
		t.Fatal("expected DRIFT error, got nil")
	}
}

// TestIntegrityRequiresAuthorization pins the gate: the command sends live
// traffic, so it must refuse without --confirm (or a trusted scope file).
func TestIntegrityRequiresAuthorization(t *testing.T) {
	t.Setenv("SECSKILLS_SCOPE", t.TempDir()+"/absent.yml")
	if err := cmdIntegrity([]string{"--store", t.TempDir() + "/bl.jsonl", "snapshot", "https://example.test"}); err == nil {
		t.Fatal("integrity snapshot ran without --confirm")
	}
}
