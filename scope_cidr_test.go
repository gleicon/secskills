package main

import (
	"net"
	"os"
	"testing"
)

func TestCIDRContains(t *testing.T) {
	ip := net.ParseIP("203.0.113.17")
	if !cidrContains("203.0.113.0/24", ip) {
		t.Error("IP in /24 must match")
	}
	if cidrContains("198.51.100.0/24", ip) {
		t.Error("IP outside the prefix must not match")
	}
	if cidrContains("example.com", ip) {
		t.Error("a hostname entry is never a CIDR match")
	}
	if cidrContains("203.0.113.0/24", nil) {
		t.Error("a nil IP (hostname target) must not match a CIDR entry")
	}
}

func TestScopeIPFilterPerAddress(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/scope.yml"
	body := `authorized: true
confirmed_by: tester
expires: 2999-01-01T00:00:00Z
targets:
  - 203.0.113.0/25
out_of_scope:
  - 203.0.113.10
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSKILLS_SCOPE", path)

	noConfirm := scopeIPFilter(false)
	// In the /25 target → allowed.
	if !noConfirm(net.ParseIP("203.0.113.5")) {
		t.Error("address inside the scoped /25 must be allowed")
	}
	// In the broader /24 but OUTSIDE the scoped /25 → refused (the over-auth bug).
	if noConfirm(net.ParseIP("203.0.113.200")) {
		t.Error("address outside the scoped /25 must be refused even if the prefix /24 was requested")
	}
	// Explicit out_of_scope → refused.
	if noConfirm(net.ParseIP("203.0.113.10")) {
		t.Error("out_of_scope address must be refused")
	}

	// --confirm authorizes broadly BUT out_of_scope still wins.
	withConfirm := scopeIPFilter(true)
	if !withConfirm(net.ParseIP("203.0.113.200")) {
		t.Error("--confirm must authorize an address with no exclusion")
	}
	if withConfirm(net.ParseIP("203.0.113.10")) {
		t.Error("out_of_scope must override --confirm")
	}
}
