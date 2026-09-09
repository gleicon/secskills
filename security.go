package main

import (
	"fmt"
	"io/fs"
	"net"
	"regexp"
	"strings"
	"syscall"
)

// fileUID returns the owning uid of a stat result on unix systems.
func fileUID(fi fs.FileInfo) (int, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}

// shellQuote wraps s in single quotes for safe shell interpolation, escaping any
// embedded single quote as '\”. Used for every host/URL that lands in a stored
// EvidenceCmd — those values originate from target-controlled DNS/HTTP data and
// must never be able to break out of the command at retest time.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// validHostRe permits only characters legal in a hostname/URL authority. Anything
// else (shell metacharacters, spaces, quotes) is rejected before the value can
// reach discovery, scope, or an evidence command.
var validHostRe = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)

// validHost reports whether a bare host (no scheme/path) is safe to use.
func validHost(h string) bool {
	h = strings.TrimSpace(h)
	return h != "" && len(h) <= 253 && validHostRe.MatchString(h)
}

// validTargetURL reports whether a URL is safe: http/https scheme and a host that
// passes validHost. Rejects everything else.
func validURLTarget(u string) bool {
	l := strings.ToLower(u)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return false
	}
	return validHost(hostOf(u))
}

// ssrfSafeURL validates a URL for the MCP fetch tool: http/https only, and the
// resolved IPs must not be private/loopback/link-local/reserved (defeats SSRF and
// DNS-rebinding by checking every resolved address). Returns nil if safe.
// allowLocalProbes lets the self-measurement harness (cmdMeasure) probe its own
// loopback corpus servers. It is set ONLY by `secskills measure`, never by any
// target-facing path, so the SSRF guard is unchanged in real engagements.
var allowLocalProbes bool

func ssrfSafeURL(rawurl string) error {
	l := strings.ToLower(rawurl)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return fmt.Errorf("scheme must be http or https")
	}
	if allowLocalProbes {
		return nil
	}
	host := hostOf(rawurl)
	if !validHost(host) {
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
