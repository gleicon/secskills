package main

import "testing"

func TestParseKEV(t *testing.T) {
	body := []byte(`{"catalogVersion":"2026.11.01","count":2,"vulnerabilities":[
		{"cveID":"CVE-2026-2000","vendorProject":"Acme","product":"Web","vulnerabilityName":"RCE","dateAdded":"2026-10-01","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2026-1000","vendorProject":"Beta","product":"DB","vulnerabilityName":"SQLi","dateAdded":"2026-09-01","knownRansomwareCampaignUse":"Unknown"}
	]}`)
	e, err := parseKEV(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 2 || e[0].CVE != "CVE-2026-1000" { // sorted by CVE
		t.Fatalf("got %+v", e)
	}
	if e[0].Vendor != "Beta" || e[1].KnownRansomware != "Known" {
		t.Errorf("fields not mapped: %+v", e)
	}
}

func TestParseKEVEmpty(t *testing.T) {
	if _, err := parseKEV([]byte(`{"vulnerabilities":[]}`)); err == nil {
		t.Fatal("empty catalog must error")
	}
}

func TestKEVDelta(t *testing.T) {
	prev := []KEVEntry{{CVE: "CVE-1"}, {CVE: "CVE-2"}}
	cur := []KEVEntry{{CVE: "CVE-2"}, {CVE: "CVE-3"}}
	ps, cs := kevSet(prev), kevSet(cur)
	if ps["CVE-3"] || !cs["CVE-3"] {
		t.Fatal("delta sets wrong")
	}
}

func TestParseEPSS(t *testing.T) {
	body := []byte(`{"status":"OK","data":[{"cve":"CVE-2026-1","epss":"0.97","percentile":"0.99"}]}`)
	s, err := parseEPSS(body)
	if err != nil || len(s) != 1 || s[0].EPSS != "0.97" {
		t.Fatalf("got %+v err %v", s, err)
	}
}
