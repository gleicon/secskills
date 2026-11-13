package probe

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestMPTCPCapableAgainstPlainListener(t *testing.T) {
	// A plain TCP listener does not negotiate MPTCP; the probe must return false
	// (or a dial error), never panic, and must not report a plain socket as MPTCP.
	// Go >= 1.24 opens MPTCP listeners by default on Linux, so opt out
	// explicitly to get a genuinely plain one.
	var lc net.ListenConfig
	lc.SetMultipathTCP(false)
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ok, err := MPTCPCapable(ln.Addr().String(), 3*time.Second)
	if err == nil && ok {
		t.Fatal("a plain TCP listener must not be reported as MPTCP-capable")
	}
}

func TestIPv4OptionsPlatformGate(t *testing.T) {
	_, err := IPv4OptionsReachable("127.0.0.1:9", 2*time.Second)
	if runtime.GOOS != "linux" {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("off Linux the probe must report ErrUnsupported, got %v", err)
		}
	}
	// On Linux a closed port yields a dial error, not ErrUnsupported — either way
	// it must not falsely claim reachability. (No assertion on the positive path
	// here; that needs a live option-accepting host.)
}
