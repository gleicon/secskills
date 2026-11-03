package probe

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// validHostRe permits only characters legal in a hostname/URL authority.
// Anything else (shell metacharacters, spaces, quotes) is rejected before the
// value can reach a probe. Mirrors the CLI's security.go guard exactly.
var validHostRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)

// ValidHost reports whether a bare host (no scheme/path) is safe to use.
func ValidHost(h string) bool {
	h = strings.TrimSpace(h)
	return h != "" && len(h) <= 253 && validHostRe.MatchString(h)
}

// HostOf returns the authority (host[:port]) of a target that may carry a
// scheme and/or path. It does not validate; pair it with ValidHost.
func HostOf(target string) string {
	s := target
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

// BlockedIP reports whether ip is in a range a target-facing probe must never
// reach: loopback, private, link-local, multicast, unspecified, plus cloud
// metadata, CGNAT, and reserved test ranges. Defeats SSRF and DNS-rebinding
// when every resolved address is checked.
func BlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, cidr := range []string{"169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "::ffff:169.254.0.0/112"} {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// SafeURL validates a URL for a non-destructive probe: http/https only, a host
// that passes ValidHost, and resolved IPs that are not blocked. When allowLocal
// is true the IP check is skipped — used only by a self-measurement harness
// against its own loopback corpus, never on a target-facing path. Returns nil
// if safe.
func SafeURL(rawurl string, allowLocal bool) error {
	l := strings.ToLower(rawurl)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return fmt.Errorf("scheme must be http or https")
	}
	if allowLocal {
		return nil
	}
	host := HostOf(rawurl)
	// HostOf keeps any :port (and IPv6 brackets); strip them before resolving,
	// or LookupIP of "ip:port" fails and the guard would reject every
	// port-bearing URL.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if !ValidHost(host) {
		return fmt.Errorf("invalid host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host")
	}
	for _, ip := range ips {
		if BlockedIP(ip) {
			return fmt.Errorf("host resolves to a blocked (private/loopback/link-local/reserved) address")
		}
	}
	return nil
}

// Guard decides whether a URL may be requested. SafeURL bound to a fixed
// allowLocal is the standard implementation; a caller can inject a stricter
// one (for example a scope-token check in Mode B).
type Guard func(rawurl string) error
