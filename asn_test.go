package main

import "testing"

func TestNormalizeASN(t *testing.T) {
	for _, in := range []string{"AS64500", "as64500", "64500"} {
		c, n, err := normalizeASN(in)
		if err != nil || c != "AS64500" || n != "64500" {
			t.Errorf("normalizeASN(%q) = %q,%q,%v", in, c, n, err)
		}
	}
	for _, bad := range []string{"", "AS", "64500x", "AS64.5"} {
		if _, _, err := normalizeASN(bad); err == nil {
			t.Errorf("normalizeASN(%q) should fail", bad)
		}
	}
}

func TestParseRIPEPrefixes(t *testing.T) {
	body := []byte(`{"data":{"prefixes":[
		{"prefix":"203.0.113.0/24"},
		{"prefix":"198.51.100.0/24"},
		{"prefix":"203.0.113.0/24"},
		{"prefix":"garbage"},
		{"prefix":"2001:db8::/32"}
	]}}`)
	pfx, err := parseRIPEPrefixes(body)
	if err != nil {
		t.Fatal(err)
	}
	// deduped, sorted, garbage dropped, v4+v6 kept
	want := []string{"198.51.100.0/24", "2001:db8::/32", "203.0.113.0/24"}
	if len(pfx) != len(want) {
		t.Fatalf("got %v, want %v", pfx, want)
	}
	for i := range want {
		if pfx[i] != want[i] {
			t.Fatalf("got %v, want %v", pfx, want)
		}
	}
}

func TestParseRIPEPrefixesEmpty(t *testing.T) {
	if _, err := parseRIPEPrefixes([]byte(`{"data":{"prefixes":[]}}`)); err == nil {
		t.Fatal("empty prefix list must error so the IRR fallback runs")
	}
}

func TestParseIRRPrefixes(t *testing.T) {
	out := `
route:      203.0.113.0/24
origin:     AS64500
route6:     2001:db8::/32
route:      203.0.113.0/24
`
	pfx := parseIRRPrefixes(out)
	if len(pfx) != 2 || pfx[0] != "2001:db8::/32" || pfx[1] != "203.0.113.0/24" {
		t.Fatalf("got %v", pfx)
	}
}

func TestDiffPrefixes(t *testing.T) {
	added, removed := diffPrefixes(
		[]string{"203.0.113.0/24", "198.51.100.0/24"},
		[]string{"203.0.113.0/24", "192.0.2.0/24"},
	)
	if len(added) != 1 || added[0] != "192.0.2.0/24" {
		t.Errorf("added = %v", added)
	}
	if len(removed) != 1 || removed[0] != "198.51.100.0/24" {
		t.Errorf("removed = %v", removed)
	}
}
