package fetch

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A credentialed request must not complete against an untrusted certificate:
// the server must never see the Authorization header.
func TestCredentialedClientVerifiesTLS(t *testing.T) {
	var sawAuth atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
	}))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("Authorization", "Bearer secret")
	if _, err := CredentialedClient().Do(req); err == nil {
		t.Fatal("credentialed request accepted a self-signed certificate")
	}
	if sawAuth.Load() {
		t.Fatal("credential reached a server with an untrusted certificate")
	}

	InsecureAuth = true
	t.Cleanup(func() { InsecureAuth = false })
	req, _ = http.NewRequest("GET", srv.URL, nil)
	if _, err := CredentialedClient().Do(req); err != nil {
		t.Fatalf("--insecure-auth opt-in still refused: %v", err)
	}
}

// Unauthenticated probes keep working against self-signed targets.
func TestNonDestructiveClientToleratesSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if _, err := NonDestructiveClient().Get(srv.URL); err != nil {
		t.Fatalf("probe client refused a self-signed cert: %v", err)
	}
}
