package exposure

import (
	"net"
	"testing"
	"time"

	"github.com/gleicon/secskills/internal/probe"
)

func TestCIDRHostCount(t *testing.T) {
	cases := map[string]int{
		"203.0.113.0/24": 256,
		"203.0.113.0/30": 4,
		"10.0.0.0/20":    4096,
	}
	for cidr, want := range cases {
		if got, err := cidrHostCount(cidr); err != nil || got != want {
			t.Errorf("cidrHostCount(%q) = %d,%v want %d", cidr, got, err, want)
		}
	}
}

func TestExpandCIDREnforcesCap(t *testing.T) {
	// /20 is exactly the cap: allowed.
	if _, err := expandCIDR("10.0.0.0/20", false); err != nil {
		t.Fatalf("/20 is the cap and must be allowed: %v", err)
	}
	// /19 exceeds the cap: refused without --allow-large.
	if _, err := expandCIDR("10.0.0.0/19", false); err == nil {
		t.Fatal("/19 exceeds the /20 cap and must be refused")
	}
	// ...but allowed with the override.
	if _, err := expandCIDR("10.0.0.0/19", true); err != nil {
		t.Fatalf("--allow-large must permit /19: %v", err)
	}
}

func TestExpandCIDRContents(t *testing.T) {
	ips, err := expandCIDR("203.0.113.0/30", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 || ips[0].String() != "203.0.113.0" || ips[3].String() != "203.0.113.3" {
		t.Fatalf("got %v", ips)
	}
}

func TestExpandCIDRRefusesIPv6(t *testing.T) {
	if _, err := expandCIDR("2001:db8::/120", false); err == nil {
		t.Fatal("IPv6 enumeration must be refused")
	}
}

func TestConnectScanReachable(t *testing.T) {
	// Bind a loopback listener and confirm the scan reports exactly that port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ips := []net.IP{net.ParseIP("127.0.0.1")}
	obs := connectScan(ips, []int{port, port + 1}, 64500, "127.0.0.0/8", nil, 4, nil)

	// The open port is observed; the (almost certainly) closed neighbor is not.
	var sawOpen bool
	for _, o := range obs {
		if o.Port == port {
			sawOpen = true
			if o.Source != "native-connect" || o.ASN != 64500 || o.Prefix != "127.0.0.0/8" {
				t.Errorf("observation missing inventory context: %+v", o)
			}
		}
	}
	if !sawOpen {
		t.Fatalf("connectScan must observe the open loopback port %d", port)
	}
}

func TestConnectScanHonorsRateGate(t *testing.T) {
	// A ticker that fires slowly must gate the sweep: a 2-dial scan through a
	// 50ms tick cannot finish in under one interval.
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	start := time.Now()
	connectScan(ips, []int{1, 2}, 0, "", tick.C, 1, nil)
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("connectScan must wait on the rate gate")
	}
}

// TestConnectScanStreamsEachHit proves the sink receives every observation as it
// is found, so a sweep killed mid-prefix keeps its progress (AC-7).
func TestConnectScanStreamsEachHit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	var streamed int
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	obs := connectScan(ips, []int{port}, 0, "", nil, 2, func(_ probe.Observation) error {
		streamed++
		return nil
	})
	if streamed != len(obs) || streamed == 0 {
		t.Fatalf("sink must fire once per hit: streamed=%d obs=%d", streamed, len(obs))
	}
}
