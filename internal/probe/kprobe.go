package probe

import (
	"errors"
	"net"
	"runtime"
	"syscall"
	"time"
)

// Kernel-reachability primitives for the kernel-CVE class (spec §7.3, e.g.
// CVE-2026-98432). Both are SINGLE non-destructive packets: they test whether a
// code path is REACHABLE, never whether it is patched, and never send a race
// trigger, exploit, or malformed sequence designed to fault a kernel (D-4). They
// license a claim like "a multipath TCP listener is reachable", not "vulnerable".

// ErrUnsupported means the probe cannot run on this platform (e.g. the IPv4
// options probe off Linux). It is not a target result — the caller reports the
// probe as not-run, never as negative.
var ErrUnsupported = errors.New("probe unsupported on this platform")

// MPTCPCapable reports whether the target negotiates Multipath TCP on a single
// connection. It uses the kernel's native MPTCP dialer (no raw socket, no
// privilege): if the listener answers MP_CAPABLE the connection upgrades and
// MultipathTCP() is true; otherwise it falls back to plain TCP and returns
// false. A reachable MPTCP listener is the setup the public PoC needs — a risk
// multiplier, observed externally.
func MPTCPCapable(addr string, timeout time.Duration) (bool, error) {
	var d net.Dialer
	d.Timeout = timeout
	d.SetMultipathTCP(true)
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		return tc.MultipathTCP()
	}
	return false, nil
}

// recordRouteOption is a minimal IPv4 Record Route option (type 7), padded to a
// 4-byte boundary with an End-of-Options byte. Carried in the SYN, it exercises
// the IPv4-option handshake path without any payload.
var recordRouteOption = []byte{0x07, 0x07, 0x04, 0, 0, 0, 0, 0x00}

// IPv4OptionsReachable reports whether a TCP handshake completes with IPv4
// options (Record Route) set on the SYN — i.e. the IPv4-option handshake path is
// reachable. This is reachability only, NEVER patch state. It sets IP_OPTIONS on
// an ordinary TCP socket via the dialer's Control hook (no raw socket); it is
// gated to Linux because option handling differs elsewhere, returning
// ErrUnsupported rather than a misleading negative.
func IPv4OptionsReachable(addr string, timeout time.Duration) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, ErrUnsupported
	}
	d := net.Dialer{
		Timeout: timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_IP, syscall.IP_OPTIONS, string(recordRouteOption))
			}); err != nil {
				return err
			}
			return serr
		},
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}
