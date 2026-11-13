package exposure

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/jsonl"
	"github.com/gleicon/secskills/internal/probe"
)

// Version enrichment (spec N-3 next step): promote an L0 observation ("port 22
// reachable") to a product and version ("OpenSSH 8.9p1") so the vulnerability
// join has something to match. Every method is read-only and single-exchange:
// read a service's own greeting, or one HTTP GET. No authentication, no payload
// beyond a protocol-mandated banner read.
//
// A version turns a reachability observation into a candidate for a CVE match;
// that match itself needs version-range feed data (NVD/OSV CPE), ingested next.
// Here we also do an honest NAME-LEVEL cross-reference against the KEV catalog:
// "this host runs a product that appears in KEV" — a lead to verify by version,
// never asserted as a confirmed vulnerability.

// sshBannerRe pulls the software token out of an SSH identification string:
// "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1" -> "OpenSSH_8.9p1".
var sshBannerRe = regexp.MustCompile(`^SSH-2\.0-(\S+)`)

// serverRe splits a Server header "nginx/1.18.0" into product and version.
var serverRe = regexp.MustCompile(`^([A-Za-z][\w .-]*?)[/ ]v?(\d[\w.]*)`)

// parseSSH turns an SSH identification string into product and version.
func parseSSH(line string) (product, version string) {
	m := sshBannerRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return "", ""
	}
	tok := m[1] // e.g. OpenSSH_8.9p1
	if p, v, ok := strings.Cut(tok, "_"); ok {
		return p, v
	}
	return tok, ""
}

// parseServer turns a Server header value into product and version.
func parseServer(server string) (product, version string) {
	m := serverRe.FindStringSubmatch(strings.TrimSpace(server))
	if m == nil {
		return strings.TrimSpace(server), ""
	}
	return strings.TrimSpace(m[1]), m[2]
}

// parseMySQLVersion extracts the server version from a MySQL initial handshake
// packet: 4-byte header, 1-byte protocol version, then a NUL-terminated version
// string.
func parseMySQLVersion(pkt []byte) string {
	if len(pkt) < 6 || pkt[4] != 10 { // protocol version 10
		return ""
	}
	rest := pkt[5:]
	if i := indexByte(rest, 0); i > 0 {
		return string(rest[:i])
	}
	return ""
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// cpeVendor maps a product name to its CPE vendor:product pair. Unknown
// products get no CPE rather than a guessed one.
var cpeVendor = map[string][2]string{
	"openssh":   {"openbsd", "openssh"},
	"nginx":     {"f5", "nginx"},
	"apache":    {"apache", "http_server"},
	"postfix":   {"postfix", "postfix"},
	"exim":      {"exim", "exim"},
	"mysql":     {"oracle", "mysql"},
	"mariadb":   {"mariadb", "mariadb"},
	"caddy":     {"caddyserver", "caddy"},
	"openresty": {"openresty", "openresty"},
	"litespeed": {"litespeedtech", "litespeed_web_server"},
}

// deriveCPE builds a CPE 2.3 string for a product/version, or "" when the
// vendor is unknown or the version is missing.
func deriveCPE(product, version string) string {
	if version == "" {
		return ""
	}
	key := strings.ToLower(strings.Fields(product)[0])
	vp, ok := cpeVendor[key]
	if !ok {
		return ""
	}
	// Version to the first non-version token (drop distro suffixes).
	v := version
	if i := strings.IndexFunc(v, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r == '.' || r == 'p')
	}); i > 0 {
		v = v[:i]
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vp[0], vp[1], v)
}

// readLine reads one line (up to a bounded size) from a freshly-dialed service
// greeting. Read-only; nothing is sent.
func readLine(addr string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	line := string(buf[:n])
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	return line
}

// readPacket reads up to n bytes of a service greeting (for binary handshakes).
func readPacket(addr string, timeout time.Duration, n int) []byte {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, n)
	got, _ := conn.Read(buf)
	return buf[:got]
}

// EnrichOne fills Product/Version/CPE on one observation by its service.
func EnrichOne(client *probe.Client, o Observation) Observation {
	addr := net.JoinHostPort(o.IP, fmt.Sprint(o.Port))
	switch o.Service {
	case "ssh":
		if p, v := parseSSH(readLine(addr, 4*time.Second)); p != "" {
			o.Product, o.Version = p, v
		}
	case "http", "https":
		base := fmt.Sprintf("%s://%s:%d/", o.Service, o.IP, o.Port)
		if _, hdr, _, ok := client.GetWithBody(base, 8192); ok && hdr != nil {
			if p, v := parseServer(hdr.Get("Server")); p != "" {
				o.Product, o.Version = p, v
			}
		}
	case "smtp", "imap", "pop3":
		line := readLine(addr, 4*time.Second)
		o.Banner = line
		o.Product = mailProduct(line)
	case "mysql":
		if v := parseMySQLVersion(readPacket(addr, 4*time.Second, 128)); v != "" {
			o.Product, o.Version = "MySQL", v
		}
	}
	if o.CPE == "" {
		o.CPE = deriveCPE(o.Product, o.Version)
	}
	o.Source = "banner"
	return o
}

func mailProduct(banner string) string {
	l := strings.ToLower(banner)
	for _, p := range []string{"postfix", "exim", "sendmail", "exchange", "dovecot", "zimbra"} {
		if strings.Contains(l, p) {
			return p
		}
	}
	return ""
}

// LoadKEVForEnrich reads the cached KEV catalog, or nil.
func LoadKEVForEnrich() []KEVEntry {
	b, err := os.ReadFile(filepath.Join(feedDir(), "kev.json"))
	if err != nil {
		return nil
	}
	var e []KEVEntry
	if jsonl.JSONUnmarshalLine(string(b), &e) {
		return e
	}
	return nil
}

// kevProductHits returns KEV CVEs whose product name matches an observed
// product (name-level only — a lead, not a confirmed match).
func kevProductHits(product string, kev []KEVEntry) []string {
	if product == "" {
		return nil
	}
	pl := strings.ToLower(product)
	var out []string
	for _, e := range kev {
		kp := strings.ToLower(e.Product)
		if kp != "" && (strings.Contains(kp, pl) || strings.Contains(pl, kp)) {
			out = append(out, e.CVE)
		}
	}
	return out
}

// ReportEnrich prints enrichment coverage and KEV product hits.
func ReportEnrich(obs []Observation, kev []KEVEntry, out string) {
	withVer, withCPE := 0, 0
	prod := map[string]int{}
	for _, o := range obs {
		if o.Version != "" {
			withVer++
		}
		if o.CPE != "" {
			withCPE++
		}
		if o.Product != "" {
			label := o.Product
			if o.Version != "" {
				label += " " + o.Version
			}
			prod[label]++
		}
	}
	fmt.Printf("enrich: %d services, %d with version, %d with CPE -> %s\n", len(obs), withVer, withCPE, out)

	type kv struct {
		k string
		v int
	}
	var top []kv
	for k, v := range prod {
		top = append(top, kv{k, v})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].v > top[j].v })
	fmt.Println("top products:")
	for i, e := range top {
		if i >= 12 {
			break
		}
		fmt.Printf("  %-32s %d\n", e.k, e.v)
	}

	// Name-level KEV cross-reference (leads to verify by version).
	if len(kev) > 0 {
		seen := map[string]bool{}
		for _, o := range obs {
			if o.Product == "" {
				continue
			}
			if hits := kevProductHits(o.Product, kev); len(hits) > 0 && !seen[o.Product] {
				seen[o.Product] = true
				fmt.Printf("  [KEV name-match] product %q appears in KEV (%d CVEs, e.g. %s) — verify by version\n",
					o.Product, len(hits), hits[0])
			}
		}
	}
}
