package main

import "testing"

// TestStableFindingKeyInvariants asserts a finding key derives from stable
// semantics: it must NOT change under scheme (http/https), trailing slash,
// default-port, or host-case variation, and MUST differ across detector, asset,
// or control. This is the retest-history contract.
func TestStableFindingKeyInvariants(t *testing.T) {
	base := &Finding{DetectorID: "http.exposure-path@1", ProbeKind: "status",
		Host: "https://api.example.com", ProbeURL: "https://api.example.com/metrics"}
	k := stableFindingKey(base)

	// must be invariant under these cosmetic variations
	invariants := []*Finding{
		{DetectorID: "http.exposure-path@1", ProbeKind: "status", Host: "http://api.example.com", ProbeURL: "http://api.example.com/metrics"},        // scheme
		{DetectorID: "http.exposure-path@1", ProbeKind: "status", Host: "https://api.example.com", ProbeURL: "https://api.example.com/metrics/"},      // trailing slash
		{DetectorID: "http.exposure-path@1", ProbeKind: "status", Host: "https://api.example.com:443", ProbeURL: "https://api.example.com:443/metrics"}, // default port
		{DetectorID: "http.exposure-path@1", ProbeKind: "status", Host: "https://API.Example.com", ProbeURL: "https://API.Example.com/metrics"},        // host case
		{DetectorID: "http.exposure-path@1", ProbeKind: "status", Host: "https://api.example.com", ProbeURL: "https://api.example.com/metrics?x=1"},    // query
	}
	for i, f := range invariants {
		if got := stableFindingKey(f); got != k {
			t.Errorf("invariant %d: key changed %s != %s", i, got, k)
		}
	}

	// must DIFFER when identity semantics differ
	differ := []*Finding{
		{DetectorID: "http.cors@1", ProbeKind: "status", Host: "https://api.example.com", ProbeURL: "https://api.example.com/metrics"},          // detector
		{DetectorID: "http.exposure-path@1", ProbeKind: "status", Host: "https://other.example.com", ProbeURL: "https://other.example.com/metrics"}, // asset
		{DetectorID: "http.exposure-path@1", ProbeKind: "status", Host: "https://api.example.com", ProbeURL: "https://api.example.com/actuator"},   // control/path
	}
	for i, f := range differ {
		if got := stableFindingKey(f); got == k {
			t.Errorf("differ %d: key collided %s == %s", i, got, k)
		}
	}

	// TLS policy: one identity per asset regardless of which weak protocol led
	tlsA := &Finding{DetectorID: "tls.deprecated-protocol@1", ProbeKind: "tls-weak", Host: "https://h.example.com", ProbeURL: "h.example.com:443", ProbeArg: "1.0"}
	tlsB := &Finding{DetectorID: "tls.deprecated-protocol@1", ProbeKind: "tls-weak", Host: "https://h.example.com", ProbeURL: "h.example.com:443", ProbeArg: "1.1"}
	if stableFindingKey(tlsA) != stableFindingKey(tlsB) {
		t.Error("TLS key should be per-asset, not per-protocol")
	}
}
