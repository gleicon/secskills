package probe

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBlockedIPRanges(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1"}
	for _, s := range blocked {
		if !BlockedIP(net.ParseIP(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	allowed := []string{"203.0.113.17", "8.8.8.8", "1.1.1.1"}
	for _, s := range allowed {
		if BlockedIP(net.ParseIP(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestSafeURLScheme(t *testing.T) {
	if err := SafeURL("ftp://example.com", false); err == nil {
		t.Fatal("non-http scheme must be rejected")
	}
	if err := SafeURL("file:///etc/passwd", false); err == nil {
		t.Fatal("file scheme must be rejected")
	}
}

func TestSafeURLAllowLocalSkipsResolution(t *testing.T) {
	if err := SafeURL("http://127.0.0.1:8080/x", true); err != nil {
		t.Fatalf("allowLocal must skip the IP check: %v", err)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com/v1/x": "api.example.com",
		"http://203.0.113.17:443/":     "203.0.113.17:443",
		"example.com/path":             "example.com",
		"[2001:db8::1]:443":            "[2001:db8::1]:443",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDialGuardBlocksRebind proves the connect-time Control hook blocks a
// blocked address even when the URL-level Guard is a no-op — the TOCTOU /
// DNS-rebinding defense. A permissive guard lets the request through; the
// dialer must still refuse to connect to loopback.
func TestDialGuardBlocksRebind(t *testing.T) {
	pass := func(string) error { return nil } // guard that approves everything
	c := NewClient(pass, "test", false)
	if _, _, _, ok := c.GetWithBody("http://127.0.0.1:9/x", 1024); ok {
		t.Fatal("connect-time guard must block a blocked address the URL guard let pass")
	}
}

func TestDialGuardAllowLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close()
	pass := func(string) error { return nil }

	// allowLocal=false: the loopback server is blocked at dial.
	if _, _, _, ok := NewClient(pass, "test", false).GetWithBody(srv.URL, 1024); ok {
		t.Fatal("allowLocal=false must block a loopback dial")
	}
	// allowLocal=true: the same dial is permitted and reaches the server.
	code, _, _, ok := NewClient(pass, "test", true).GetWithBody(srv.URL, 1024)
	if !ok || code != 204 {
		t.Fatalf("allowLocal=true must reach the loopback server: ok=%v code=%d", ok, code)
	}
}
