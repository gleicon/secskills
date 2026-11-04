package main

import (
	"net"
	"testing"
	"time"
)

func sampleToken() ScopeToken {
	return ScopeToken{
		Tenant: "t_8f2a", ASN: 64500, Prefixes: []string{"203.0.113.0/24"},
		NotBefore: "2026-11-01T00:00:00Z", NotAfter: "2099-01-01T00:00:00Z",
		MaxPPS: 40, AllowedClasses: []string{"cve", "tls", "exposure"}, Intrusive: false,
		IssuedBy: "orchestrator",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := []byte("shared-secret")
	signed, err := sampleToken().Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Sig == "" {
		t.Fatal("sign must set a signature")
	}
	if err := signed.Verify(key); err != nil {
		t.Fatalf("verify must pass for the signing key: %v", err)
	}
	if signed.Verify([]byte("wrong-key")) == nil {
		t.Fatal("verify must fail for a different key")
	}
}

func TestTamperBreaksSignature(t *testing.T) {
	key := []byte("k")
	signed, _ := sampleToken().Sign(key)
	signed.Prefixes = []string{"0.0.0.0/0"} // widen scope after signing
	if signed.Verify(key) == nil {
		t.Fatal("tampering with prefixes must invalidate the signature")
	}
}

func TestAuthorizes(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	tok := sampleToken()

	if ok, _ := tok.Authorizes(net.ParseIP("203.0.113.17"), "cve", now); !ok {
		t.Error("in-prefix, in-window, allowed class must authorize")
	}
	if ok, _ := tok.Authorizes(net.ParseIP("8.8.8.8"), "cve", now); ok {
		t.Error("out-of-prefix must be refused")
	}
	if ok, _ := tok.Authorizes(net.ParseIP("203.0.113.17"), "exploit", now); ok {
		t.Error("class not in allowed_classes must be refused")
	}
	early := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if ok, _ := tok.Authorizes(net.ParseIP("203.0.113.17"), "cve", early); ok {
		t.Error("before the window must be refused")
	}
}

func TestIntrusiveTokenRefused(t *testing.T) {
	tok := sampleToken()
	tok.Intrusive = true
	if ok, why := tok.Authorizes(net.ParseIP("203.0.113.17"), "cve", time.Now()); ok {
		t.Fatalf("intrusive token must be refused regardless (D-4): %s", why)
	}
}
