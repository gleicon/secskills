package main

import (
	"net"
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
