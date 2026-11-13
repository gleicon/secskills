package netsec

import (
	"net"
	"testing"
)

func TestSSRFSafeURLRefusesUnsafeTargets(t *testing.T) {
	for _, u := range []string{
		"ftp://example.com/",
		"file:///etc/passwd",
		"gopher://127.0.0.1/",
		"http://127.0.0.1/",
		"http://127.1.2.3:8080/x",
		"http://localhost/",
		"http://10.0.0.1/",
		"http://172.16.5.4/",
		"http://192.168.1.1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.64.0.1/",
		"http://198.18.0.1/",
		"http://0.0.0.0/",
		"http://[::1]/",
		"http://host;rm -rf /",
		"http://host name/",
		"http://`id`/",
	} {
		if err := SSRFSafeURL(u); err == nil {
			t.Errorf("SSRFSafeURL(%q) = nil, want refusal", u)
		}
	}
}

func TestSSRFSafeURLAllowsPublicLiteral(t *testing.T) {
	// IP literals resolve without DNS, so this stays offline.
	for _, u := range []string{"http://8.8.8.8/", "https://1.1.1.1:443/x?y=z"} {
		if err := SSRFSafeURL(u); err != nil {
			t.Errorf("SSRFSafeURL(%q) = %v, want nil", u, err)
		}
	}
}

func TestAllowLocalProbesKeepsSchemeCheck(t *testing.T) {
	AllowLocalProbes = true
	t.Cleanup(func() { AllowLocalProbes = false })
	if err := SSRFSafeURL("http://127.0.0.1:1234/"); err != nil {
		t.Errorf("loopback refused with AllowLocalProbes: %v", err)
	}
	if err := SSRFSafeURL("file:///etc/passwd"); err == nil {
		t.Error("file:// allowed with AllowLocalProbes")
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "10.1.2.3", "192.168.0.1", "172.31.255.255", "169.254.169.254",
		"100.64.0.1", "192.0.0.8", "198.19.1.1", "0.0.0.0", "::", "fe80::1", "fc00::1", "224.0.0.1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254"}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = false", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "203.0.113.10", "2001:4860:4860::8888"} {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = true", s)
		}
	}
}

func TestShellQuoteCannotBreakOut(t *testing.T) {
	cases := map[string]string{
		"plain":               "'plain'",
		"it's":                `'it'\''s'`,
		"a'; rm -rf / #":      `'a'\''; rm -rf / #'`,
		"$(id) `id` \"q\" \\": `'$(id) ` + "`id`" + ` "q" \'`,
		"":                    "''",
	}
	for in, want := range cases {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestValidHost(t *testing.T) {
	for _, h := range []string{"example.com", "a-b.example.co.uk", "203.0.113.1", "host:8443", "[2001:db8::1]"} {
		if !ValidHost(h) {
			t.Errorf("ValidHost(%q) = false", h)
		}
	}
	for _, h := range []string{"", " ", "a b", "x;y", "x|y", "x$(y)", "x'y", "x\"y", "x/y", string(make([]byte, 254))} {
		if ValidHost(h) {
			t.Errorf("ValidHost(%q) = true", h)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://example.com/a/b": "example.com",
		"http://example.com:8080": "example.com",
		"example.com:443":         "example.com",
		"example.com":             "example.com",
		"https://203.0.113.5/x":   "203.0.113.5",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
