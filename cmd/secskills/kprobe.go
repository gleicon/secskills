package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/probe"
	"github.com/gleicon/secskills/internal/scope"
)

// cmdKProbe runs the §7.3 kernel-reachability primitives against ONE target,
// deliberately and gated — never swept across a prefix. Both are single
// non-destructive packets (D-4). The result feeds the matcher as asset facts
// (MPTCPCapable raises a reachable Linux host to the L1 risk tier for the kernel
// CVE class); it never asserts patch state.
func cmdKProbe(args []string) error {
	fs := flag.NewFlagSet("kprobe", flag.ContinueOnError)
	ip := fs.String("ip", "", "target IP")
	port := fs.Int("port", 0, "target TCP port")
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ip == "" || *port == 0 {
		return fmt.Errorf("usage: secskills kprobe --ip <ip> --port <p> --confirm")
	}
	if err := scope.GateNotice("kprobe", fmt.Sprintf("%s:%d", *ip, *port), *confirm); err != nil {
		return err
	}
	addr := net.JoinHostPort(*ip, fmt.Sprint(*port))

	asset := intel.Asset{IP: *ip, OS: "", ReachableTCP: true}

	mptcp, err := probe.MPTCPCapable(addr, 4*time.Second)
	switch {
	case err != nil:
		fmt.Printf("  mptcp-capable@1    : not determined (%v)\n", err)
	case mptcp:
		asset.MPTCPCapable = true
		fmt.Printf("  mptcp-capable@1    : YES — a multipath TCP listener is reachable (PoC setup; risk multiplier)\n")
	default:
		fmt.Printf("  mptcp-capable@1    : no\n")
	}

	opt, err := probe.IPv4OptionsReachable(addr, 4*time.Second)
	switch {
	case errors.Is(err, probe.ErrUnsupported):
		fmt.Printf("  ipv4-options-echo@1: not run (%v)\n", err)
	case err != nil:
		fmt.Printf("  ipv4-options-echo@1: path not reachable (%v)\n", err)
	case opt:
		fmt.Printf("  ipv4-options-echo@1: YES — the IPv4-option handshake path is reachable (reachability only, NOT patch state)\n")
	default:
		fmt.Printf("  ipv4-options-echo@1: no\n")
	}

	b, _ := json.Marshal(asset)
	fmt.Printf("asset-facts: %s\n", b)
	return nil
}
