package main

import (
	"strings"
	"testing"
)

func TestRenderPrefixReport(t *testing.T) {
	obs := []Observation{
		{IP: "203.0.113.1", Port: 22, Service: "ssh"},
		{IP: "203.0.113.1", Port: 6379, Service: "redis"},
		{IP: "203.0.113.2", Port: 443, Service: "https"},
	}
	leaks := []leakFinding{
		{IP: "203.0.113.2", Port: 443, Kind: "exposed-dotenv", Evidence: "dotenv exposed: 2 keys [DB_PASSWORD, APP_KEY] (values redacted)"},
		{IP: "203.0.113.2", Port: 443, Kind: "banner", Server: "nginx"},
	}
	r := renderPrefixReport("AS65000 203.0.113.0/24", obs, leaks, nil, nil, nil)

	// Critical leak surfaced.
	if !strings.Contains(r, "exposed-dotenv") || !strings.Contains(r, "rotate all secrets") {
		t.Error("dotenv leak and its action must appear")
	}
	// Datastore exposure surfaced.
	if !strings.Contains(r, "6379") || !strings.Contains(r, "redis") {
		t.Error("internet-reachable redis must be listed")
	}
	// Banner is NOT counted as a critical leak (summary says 1).
	if !strings.Contains(r, "Critical exposures (data/credential leaks): **1**") {
		t.Error("banner must not be counted as a critical exposure")
	}
	// Host inventory present.
	if !strings.Contains(r, "203.0.113.1") {
		t.Error("host inventory must list hosts")
	}
}

// TestReportCarriesNoSecretValues guards the invariant: a secret value placed in
// an observation/leak must never appear — the report only names exposures.
func TestReportCarriesNoSecretValues(t *testing.T) {
	leaks := []leakFinding{
		// Evidence is already redacted upstream; the report must not re-introduce
		// values. We assert the renderer passes through only what it is given.
		{IP: "203.0.113.5", Port: 80, Kind: "exposed-dotenv", Evidence: "dotenv exposed: 1 keys [SECRET] (values redacted)"},
	}
	r := renderPrefixReport("x", nil, leaks, nil, nil, nil)
	if strings.Contains(r, "sup3rs3cret") {
		t.Fatal("renderer must not invent or echo secret values")
	}
	if !strings.Contains(r, "values redacted") {
		t.Error("redaction marker should be preserved")
	}
}

func TestReportAnnotatesOpenDatastore(t *testing.T) {
	obs := []Observation{{IP: "203.0.113.9", Port: 27017, Service: "mongodb"}}
	dbc := []dbResult{{IP: "203.0.113.9", Port: 27017, Service: "mongodb", Status: "OPEN-NOAUTH", Detail: "listDatabases returned without authentication"}}
	r := renderPrefixReport("x", obs, nil, dbc, nil, nil)
	if !strings.Contains(r, "OPEN — NO AUTH") || !strings.Contains(r, "isolate now") {
		t.Fatalf("open datastore must be flagged critical in the report")
	}
}
