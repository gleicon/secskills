package exposure

import "testing"

func TestParseSSH(t *testing.T) {
	cases := map[string][2]string{
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1": {"OpenSSH", "8.9p1"},
		"SSH-2.0-OpenSSH_7.4":                     {"OpenSSH", "7.4"},
		"SSH-2.0-dropbear_2020.81":                {"dropbear", "2020.81"},
		"garbage":                                 {"", ""},
	}
	for in, want := range cases {
		p, v := parseSSH(in)
		if p != want[0] || v != want[1] {
			t.Errorf("parseSSH(%q) = %q,%q want %q,%q", in, p, v, want[0], want[1])
		}
	}
}

func TestParseServer(t *testing.T) {
	cases := map[string][2]string{
		"nginx/1.18.0":           {"nginx", "1.18.0"},
		"Apache/2.4.41 (Ubuntu)": {"Apache", "2.4.41"},
		"cloudflare":             {"cloudflare", ""},
		"openresty/1.21.4.1":     {"openresty", "1.21.4.1"},
	}
	for in, want := range cases {
		p, v := parseServer(in)
		if p != want[0] || v != want[1] {
			t.Errorf("parseServer(%q) = %q,%q want %q,%q", in, p, v, want[0], want[1])
		}
	}
}

func TestParseMySQLVersion(t *testing.T) {
	// header(4) + protocol(10) + "8.0.32\0"
	pkt := []byte{0x0a, 0, 0, 0, 10}
	pkt = append(pkt, []byte("8.0.32")...)
	pkt = append(pkt, 0)
	if v := parseMySQLVersion(pkt); v != "8.0.32" {
		t.Fatalf("got %q", v)
	}
	if v := parseMySQLVersion([]byte{1, 2, 3}); v != "" {
		t.Errorf("short packet must yield empty, got %q", v)
	}
}

func TestDeriveCPE(t *testing.T) {
	if got := deriveCPE("OpenSSH", "8.9p1"); got != "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*" {
		t.Errorf("openssh cpe wrong: %q", got)
	}
	if got := deriveCPE("nginx", "1.18.0"); got != "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*" {
		t.Errorf("nginx cpe wrong: %q", got)
	}
	if deriveCPE("nginx", "") != "" {
		t.Error("no version -> no cpe")
	}
	if deriveCPE("SomeUnknownThing", "1.0") != "" {
		t.Error("unknown vendor -> no cpe")
	}
}

func TestKEVProductHits(t *testing.T) {
	kev := []KEVEntry{{CVE: "CVE-1", Product: "Exim"}, {CVE: "CVE-2", Product: "HTTP Server"}}
	if h := kevProductHits("exim", kev); len(h) != 1 || h[0] != "CVE-1" {
		t.Errorf("exim must match: %v", h)
	}
	if h := kevProductHits("nginx", kev); len(h) != 0 {
		t.Errorf("nginx must not match: %v", h)
	}
}
