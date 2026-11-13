package fetch

import (
	"encoding/json"
	"net/url"
	"strings"
)

// crtEntry is one certificate-transparency record from crt.sh's JSON output.
type crtEntry struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

// CrtshNames queries crt.sh (throttled) and returns the unique hostnames present
// in issued-certificate SANs for the domain. Parsed with encoding/json rather
// than by hand, so malformed/edge records don't leak junk hostnames.
func CrtshNames(domain string) []string {
	body, err := HTTPDo("crtsh", "GET", "https://crt.sh/?q=%25."+url.QueryEscape(domain)+"&output=json", "", 3)
	if err != nil {
		return nil
	}
	var entries []crtEntry
	if json.Unmarshal(body, &entries) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		for _, raw := range append(strings.Split(e.NameValue, "\n"), e.CommonName) {
			h := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(raw, "*.")))
			if h != "" && !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}
