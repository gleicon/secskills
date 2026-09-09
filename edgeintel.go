package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// M8 — Origin looking-glass depth.
// Two additions that strengthen origin discovery without a new dependency:
//  1. Leaf-certificate SHA-256 correlation — the strongest same-origin proof:
//     if a candidate IP presents the SAME leaf certificate as the target's edge,
//     it is almost certainly the same service (far stronger than a title match).
//  2. Censys adapter (key-gated, like Shodan) to widen the origin-candidate net.
//
// JARM/JA3 active TLS fingerprinting is tracked as future work: it requires
// crafting raw TLS ClientHello variants that crypto/tls does not expose, so it
// needs a raw-TLS library and is out of the stdlib-only constraint.

// leafCertSHA256 dials host:443 (SNI = sniName) and returns the SHA-256 of the
// leaf certificate. Empty on failure.
func leafCertSHA256(dialHost, sniName string) string {
	d := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", dialHost+":443",
		&tls.Config{InsecureSkipVerify: true, ServerName: sniName})
	if err != nil {
		return ""
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
	return fmt.Sprintf("%x", sum)
}

// sameLeafCert reports whether a candidate IP serves the same leaf certificate as
// the target's edge (SNI = target). Strong same-origin signal.
func sameLeafCert(target, candidateIP string) (bool, string) {
	edge := leafCertSHA256(target, target)
	if edge == "" {
		return false, ""
	}
	cand := leafCertSHA256(candidateIP, target)
	if cand == "" {
		return false, ""
	}
	return edge == cand, cand
}

// --- Censys adapter (key-gated) --------------------------------------------

func censysReady() bool {
	return os.Getenv("CENSYS_API_ID") != "" && os.Getenv("CENSYS_API_SECRET") != ""
}

// censysSearchIPs queries the Censys Hosts search API for a query (e.g. a service
// name or certificate) and returns matching IPs. Empty unless credentials are set.
func censysSearchIPs(query string, limit int) []string {
	if !censysReady() {
		return nil
	}
	id := os.Getenv("CENSYS_API_ID")
	secret := os.Getenv("CENSYS_API_SECRET")
	body := fmt.Sprintf(`{"q":%q,"per_page":%d}`, query, limit)
	req, err := http.NewRequest("POST", "https://search.censys.io/api/v2/hosts/search", strings.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var r struct {
		Result struct {
			Hits []struct {
				IP string `json:"ip"`
			} `json:"hits"`
		} `json:"result"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil {
		return nil
	}
	var ips []string
	for _, h := range r.Result.Hits {
		if net.ParseIP(h.IP) != nil {
			ips = append(ips, h.IP)
		}
	}
	return ips
}
