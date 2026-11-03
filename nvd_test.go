package main

import "testing"

const nvdSample = `{"vulnerabilities":[
 {"cve":{"id":"CVE-2021-23017","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]},
   "configurations":[{"nodes":[{"cpeMatch":[
     {"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*","versionStartIncluding":"0.6.18","versionEndIncluding":"1.20.0"},
     {"vulnerable":false,"criteria":"cpe:2.3:o:other:thing:*","versionEndIncluding":"9.9.9"}
   ]}]}]}},
 {"cve":{"id":"CVE-2019-9511","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]},
   "configurations":[{"nodes":[{"cpeMatch":[
     {"vulnerable":true,"criteria":"cpe:2.3:a:apple:swiftnio:*","versionEndExcluding":"1.0.0"}
   ]}]}]}}
]}`

func TestParseNVD(t *testing.T) {
	ranges, err := parseNVD([]byte(nvdSample), "f5", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 1 {
		t.Fatalf("want 1 nginx range, got %d: %+v", len(ranges), ranges)
	}
	r := ranges[0]
	if r.CVE != "CVE-2021-23017" || r.CVSS != 9.8 || r.VersionEndIncluding != "1.20.0" {
		t.Errorf("fields not mapped: %+v", r)
	}
	// non-matching product filtered out; non-vulnerable match ignored.
	apple, _ := parseNVD([]byte(nvdSample), "apple", "swiftnio")
	if len(apple) != 1 {
		t.Error("apple product should parse its own range")
	}
}

func TestCpeVendorProduct(t *testing.T) {
	v, p := cpeVendorProduct("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
	if v != "f5" || p != "nginx" {
		t.Errorf("got %q %q", v, p)
	}
}

func TestParseNVDExactVersion(t *testing.T) {
	// CVE-2021-41773 affects exactly Apache 2.4.49 — version pinned in the CPE,
	// no range bounds. Must become an exact match, not "all versions".
	body := `{"vulnerabilities":[{"cve":{"id":"CVE-2021-41773","configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
	]}]}]}}]}`
	rs, err := parseNVD([]byte(body), "apache", "http_server")
	if err != nil || len(rs) != 1 {
		t.Fatalf("got %d ranges, err %v", len(rs), err)
	}
	if rs[0].VersionStartIncluding != "2.4.49" || rs[0].VersionEndIncluding != "2.4.49" {
		t.Fatalf("exact version not pinned: %+v", rs[0])
	}
	if !rs[0].InRange("2.4.49") || rs[0].InRange("2.4.58") {
		t.Fatal("exact match must cover only 2.4.49")
	}
}

func TestParseNVDSkipsUnboundedStar(t *testing.T) {
	body := `{"vulnerabilities":[{"cve":{"id":"CVE-X","configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}
	]}]}]}}]}`
	rs, _ := parseNVD([]byte(body), "f5", "nginx")
	if len(rs) != 0 {
		t.Fatalf("a bare * with no bounds must be skipped, got %+v", rs)
	}
}
