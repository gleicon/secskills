package fetch

import (
	"testing"
	"time"
)

func TestSourceInterval(t *testing.T) {
	if sourceInterval("crtsh") != 2*time.Second {
		t.Error("crtsh interval should be 2s")
	}
	if sourceInterval("osv") != 200*time.Millisecond {
		t.Error("osv interval should be 200ms")
	}
	if sourceInterval("unknown") != time.Second {
		t.Error("default interval should be 1s")
	}
}
