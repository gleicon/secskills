package main

import (
	"encoding/base64"
	"net"
	"net/http"
	"os/exec"
	"strings"
)

// Edge & Defense Reconnaissance ("throw a net").
// Fingerprint the CDN/WAF in front of a target, then use open data (Shodan +
// favicon/cert pivots) as a looking glass to find origin IPs that leak *behind*
// the edge, and test trusted-header ACL bypasses (the WAF-vs-origin header
// parser-differential class). All GET-only and bounded.

// --- Edge fingerprinting ---------------------------------------------------

type edgeInfo struct {
	CDN string
	WAF string
	Via string
}

var edgeHeaderSigs = []struct {
	vendor, kind, header, contains string
}{
	{"Cloudflare", "cdn+waf", "Server", "cloudflare"},
	{"Cloudflare", "cdn+waf", "CF-Ray", ""},
	{"Cloudflare", "cdn+waf", "CF-Cache-Status", ""},
	{"Amazon CloudFront", "cdn", "X-Amz-Cf-Id", ""},
	{"Amazon CloudFront", "cdn", "Via", "cloudfront"},
	{"Akamai", "cdn+waf", "X-Akamai-Transformed", ""},
	{"Akamai", "cdn", "Server", "akamaighost"},
	{"Fastly", "cdn", "X-Served-By", "cache-"},
	{"Fastly", "cdn", "X-Fastly-Request-ID", ""},
	{"Sucuri", "waf", "X-Sucuri-ID", ""},
	{"Imperva/Incapsula", "waf", "X-Iinfo", ""},
	{"Imperva/Incapsula", "waf", "X-CDN", "Incapsula"},
	{"F5 BIG-IP ASM", "waf", "Server", "bigip"},
	{"Barracuda", "waf", "Server", "barracuda"},
	{"AWS WAF", "waf", "X-Amzn-Trace-Id", ""},
	{"Azure Front Door", "cdn+waf", "X-Azure-Ref", ""},
	{"Google Cloud", "cdn", "Via", "google"},
	{"Vercel", "cdn", "Server", "vercel"},
	{"Netlify", "cdn", "Server", "netlify"},
}

var edgeCookieSigs = []struct{ vendor, cookie string }{
	{"Cloudflare", "__cfduid"}, {"Cloudflare", "cf_clearance"},
	{"Imperva/Incapsula", "incap_ses"}, {"Imperva/Incapsula", "visid_incap"},
	{"F5 BIG-IP", "BIGipServer"}, {"Citrix NetScaler", "citrix_ns_id"},
}

func fingerprintEdge(hdr http.Header) edgeInfo {
	var e edgeInfo
	setKind := func(vendor, kind string) {
		if strings.Contains(kind, "waf") && e.WAF == "" {
			e.WAF = vendor
		}
		if strings.Contains(kind, "cdn") && e.CDN == "" {
			e.CDN = vendor
		}
	}
	for _, s := range edgeHeaderSigs {
		v := hdr.Get(s.header)
		if v == "" {
			continue
		}
		if s.contains == "" || strings.Contains(strings.ToLower(v), s.contains) {
			setKind(s.vendor, s.kind)
		}
	}
	cookies := strings.ToLower(strings.Join(hdr.Values("Set-Cookie"), "; "))
	for _, s := range edgeCookieSigs {
		if strings.Contains(cookies, strings.ToLower(s.cookie)) {
			if e.WAF == "" {
				e.WAF = s.vendor
			}
		}
	}
	e.Via = hdr.Get("Via")
	return e
}

// --- Favicon hash (Shodan-compatible mmh3 of base64 favicon) ---------------

func faviconHash(base string) (int32, bool) {
	u := strings.TrimRight(base, "/") + "/favicon.ico"
	code, _, body, ok := getWithBody(u, 256*1024)
	if !ok || code != 200 || len(body) == 0 {
		return 0, false
	}
	// Shodan encodes the body as base64 with trailing newline, then mmh3-32.
	b64 := base64.StdEncoding.EncodeToString([]byte(body))
	var chunked strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		chunked.WriteString(b64[i:end])
		chunked.WriteByte('\n')
	}
	return mmh3_32([]byte(chunked.String()), 0), true
}

// mmh3_32 is the 32-bit MurmurHash3 (x86) used by Shodan's http.favicon.hash.
func mmh3_32(data []byte, seed uint32) int32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// --- Looking glass: Shodan origin candidate search -------------------------

// shodanSearchIPs runs a Shodan search and returns matching IPs (bounded).
func shodanSearchIPs(query string, limit int) []string {
	if !shodanReady() {
		return nil
	}
	ctx := exec.Command("shodan", "search", "--fields", "ip_str", "--limit", itoa(limit), query)
	out, err := ctx.Output()
	if err != nil {
		return nil
	}
	var ips []string
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ip := strings.TrimSpace(l)
		if net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// cdnASN names whose IPs are edge nodes, not origin. A candidate NOT in a CDN
// ASN is a potential origin that leaks behind the edge.
var cdnOrgHints = []string{"cloudflare", "akamai", "fastly", "amazon", "cloudfront", "google", "microsoft", "azure", "incapsula", "imperva", "sucuri", "stackpath", "edgecast", "verizon", "limelight"}

func looksLikeCDN(org string) bool {
	o := strings.ToLower(org)
	for _, h := range cdnOrgHints {
		if strings.Contains(o, h) {
			return true
		}
	}
	return false
}
