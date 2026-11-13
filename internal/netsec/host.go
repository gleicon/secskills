package netsec

import (
	"strings"
)

// HostOf extracts the bare host from a URL/host:port.
func HostOf(target string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}
