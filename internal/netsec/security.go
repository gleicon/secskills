package netsec

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ShellQuote wraps s in single quotes for safe shell interpolation, escaping any
// embedded single quote as '\”. Used for every host/URL that lands in a stored
// EvidenceCmd — those values originate from target-controlled DNS/HTTP data and
// must never be able to break out of the command at retest time.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// validHostRe permits only characters legal in a hostname/URL authority. Anything
// else (shell metacharacters, spaces, quotes) is rejected before the value can
// reach discovery, scope, or an evidence command.
var validHostRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)

// ValidHost reports whether a bare host (no scheme/path) is safe to use.
func ValidHost(h string) bool {
	h = strings.TrimSpace(h)
	return h != "" && len(h) <= 253 && validHostRe.MatchString(h)
}

// AllowLocalProbes lets the self-measurement harness (measure) probe its own
// loopback corpus servers. It is set ONLY by `secskills measure`, never by any
// target-facing path, so the SSRF guard is unchanged in real engagements.
var AllowLocalProbes bool

// SSRFSafeURL validates a URL for outbound requests: http/https only, and the
// resolved IPs must not be private/loopback/link-local/reserved (defeats SSRF and
// DNS-rebinding by checking every resolved address). Returns nil if safe.
func SSRFSafeURL(rawurl string) error {
	l := strings.ToLower(rawurl)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return fmt.Errorf("scheme must be http or https")
	}
	if AllowLocalProbes {
		return nil
	}
	host := HostOf(rawurl)
	if !ValidHost(host) {
		return fmt.Errorf("invalid host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host")
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("host resolves to a blocked (private/loopback/link-local/reserved) address")
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// cloud metadata + CGNAT + reserved test ranges
	for _, cidr := range []string{"169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "::ffff:169.254.0.0/112"} {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
