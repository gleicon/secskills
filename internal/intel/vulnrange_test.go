package intel

import "testing"

func TestVercmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.18.0", "1.21.0", -1},
		{"1.21.0", "1.18.0", 1},
		{"2.4.52", "2.4.52", 0},
		{"9.6p1", "9.6", 1},
		{"9.6p1", "9.6p2", -1},
		{"1.24.0", "1.24", 1},
	}
	for _, c := range cases {
		if got := vercmp(c.a, c.b); got != c.want {
			t.Errorf("vercmp(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestInRange(t *testing.T) {
	// affected: >= 1.0.0, < 1.21.0
	r := VulnRange{VersionStartIncluding: "1.0.0", VersionEndExcluding: "1.21.0"}
	if !r.InRange("1.18.0") {
		t.Error("1.18.0 is affected")
	}
	if r.InRange("1.21.0") {
		t.Error("1.21.0 is the fixed version, excluded")
	}
	if r.InRange("1.24.0") {
		t.Error("1.24.0 is not affected")
	}
	if r.InRange("0.9.0") {
		t.Error("0.9.0 is below the start")
	}
	// unbounded: all versions affected
	all := VulnRange{}
	if !all.InRange("5.5.5") {
		t.Error("an unbounded range matches every version")
	}
}

func TestMatchProductVersionInferred(t *testing.T) {
	ranges := []VulnRange{
		{CVE: "CVE-2021-23017", Product: "nginx", VersionStartIncluding: "0.6.18", VersionEndIncluding: "1.20.0", CVSS: 9.8},
		{CVE: "CVE-2019-20372", Product: "nginx", VersionStartIncluding: "0.7.12", VersionEndExcluding: "1.17.7"},
	}
	// nginx 1.18.0: in CVE-2021-23017 (<=1.20.0) but NOT CVE-2019-20372 (<1.17.7).
	cands := MatchProduct("203.0.113.5", "nginx", "1.18.0", ranges)
	if len(cands) != 1 || cands[0].CVE != "CVE-2021-23017" {
		t.Fatalf("got %+v", cands)
	}
	c := cands[0]
	if c.Tier != "L1" || c.PatchState != "unknown" {
		t.Errorf("version-inferred must be L1/unknown, got %s/%s", c.Tier, c.PatchState)
	}
	// nginx 1.24.0: affected by neither.
	if got := MatchProduct("x", "nginx", "1.24.0", ranges); len(got) != 0 {
		t.Errorf("1.24.0 must match nothing, got %+v", got)
	}
}

func TestMatchProductApacheMapping(t *testing.T) {
	ranges := []VulnRange{{CVE: "CVE-2021-40438", Product: "http_server", VersionEndIncluding: "2.4.48"}}
	if got := MatchProduct("x", "Apache", "2.4.41", ranges); len(got) != 1 {
		t.Errorf("Apache banner must map to http_server CPE: %+v", got)
	}
	if got := MatchProduct("x", "Apache", "2.4.58", ranges); len(got) != 0 {
		t.Errorf("2.4.58 is past the fix, must not match: %+v", got)
	}
}
