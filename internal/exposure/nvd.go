package exposure

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/intel"
)

// NVD 2.0 ingest (spec §8.1): fetch a product's CVE version ranges and cache
// them as intel.VulnRange, so enriched observations can be matched by version.
// Parsing is isolated in parseNVD and unit-tested against a committed sample —
// the network call is a thin wrapper. OSINT endpoint; no gate.

// nvdResponse is the subset of the NVD 2.0 CVE API we consume.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID      string `json:"id"`
			Metrics struct {
				V31 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []struct {
						Vulnerable            bool   `json:"vulnerable"`
						Criteria              string `json:"criteria"`
						VersionStartIncluding string `json:"versionStartIncluding"`
						VersionStartExcluding string `json:"versionStartExcluding"`
						VersionEndIncluding   string `json:"versionEndIncluding"`
						VersionEndExcluding   string `json:"versionEndExcluding"`
					} `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// cpeVendorProduct splits a CPE 2.3 criteria string into vendor and product.
func cpeVendorProduct(cpe string) (vendor, product string) {
	v, p, _ := cpeParts(cpe)
	return v, p
}

// cpeParts splits a CPE 2.3 criteria string into vendor, product, and the
// version field (field 6). A version of "*" or "-" means "not pinned here" —
// the affected set is then given by the separate versionStart/End bounds.
func cpeParts(cpe string) (vendor, product, version string) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 || parts[0] != "cpe" {
		return "", "", ""
	}
	return parts[3], parts[4], parts[5]
}

// parseNVD turns an NVD 2.0 response into VulnRanges for the given vendor and
// product, keeping only vulnerable cpeMatch entries that name that product.
func parseNVD(body []byte, vendor, product string) ([]intel.VulnRange, error) {
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	var out []intel.VulnRange
	for _, v := range r.Vulnerabilities {
		cvss := 0.0
		if len(v.CVE.Metrics.V31) > 0 {
			cvss = v.CVE.Metrics.V31[0].CVSSData.BaseScore
		}
		for _, cfg := range v.CVE.Configurations {
			for _, node := range cfg.Nodes {
				for _, m := range node.CPEMatch {
					if !m.Vulnerable {
						continue
					}
					cv, cp, cver := cpeParts(m.Criteria)
					if cp != product || (vendor != "" && cv != vendor) {
						continue
					}
					vr := intel.VulnRange{
						CVE: v.CVE.ID, Vendor: cv, Product: cp,
						VersionStartIncluding: m.VersionStartIncluding,
						VersionStartExcluding: m.VersionStartExcluding,
						VersionEndIncluding:   m.VersionEndIncluding,
						VersionEndExcluding:   m.VersionEndExcluding,
						CVSS:                  cvss,
					}
					noBounds := vr.VersionStartIncluding == "" && vr.VersionStartExcluding == "" &&
						vr.VersionEndIncluding == "" && vr.VersionEndExcluding == ""
					switch {
					case cver != "*" && cver != "-" && cver != "" && noBounds:
						// Exact version pinned in the CPE: the CVE affects only
						// that version. Without this it reads as "all versions".
						vr.VersionStartIncluding, vr.VersionEndIncluding = cver, cver
					case cver == "*" && noBounds:
						// Bare "*" with no bounds is a non-specific match (often
						// an "or" component), not a vulnerable range — skip it.
						continue
					}
					out = append(out, vr)
				}
			}
		}
	}
	return out, nil
}

// nvdCachePath is where a product's ranges are cached.
func nvdCachePath(vendor, product string) string {
	return filepath.Join(feedDir(), fmt.Sprintf("nvd-%s-%s.json", vendor, product))
}

// FeedNVD fetches and caches NVD version ranges for one product.
func FeedNVD(args []string) error {
	fs := flag.NewFlagSet("feed nvd", flag.ContinueOnError)
	product := fs.String("product", "", "product name as observed (e.g. openssh, nginx, Apache)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *product == "" {
		return fmt.Errorf("usage: secskills feed nvd --product <name>")
	}
	vp, ok := cpeVendor[strings.ToLower(strings.Fields(*product)[0])]
	if !ok {
		return fmt.Errorf("no CPE vendor mapping for %q (extend cpeVendor)", *product)
	}
	vendor, prod := vp[0], vp[1]
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:" + vendor + ":" + prod
	body, err := fetch.HTTPDo("nvd", "GET", url, "", 2)
	if err != nil {
		return fmt.Errorf("fetch NVD: %w", err)
	}
	ranges, err := parseNVD(body, vendor, prod)
	if err != nil {
		return err
	}
	os.MkdirAll(feedDir(), 0o755)
	b, _ := json.MarshalIndent(ranges, "", "  ")
	path := nvdCachePath(vendor, prod)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("[nvd] %s:%s -> %d version ranges -> %s\n", vendor, prod, len(ranges), path)
	return nil
}

// LoadVulnRanges reads every cached NVD range file, for the cvematch join.
func LoadVulnRanges() []intel.VulnRange {
	entries, err := os.ReadDir(feedDir())
	if err != nil {
		return nil
	}
	var all []intel.VulnRange
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "nvd-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(feedDir(), e.Name()))
		if err != nil {
			continue
		}
		var rs []intel.VulnRange
		if json.Unmarshal(b, &rs) == nil {
			all = append(all, rs...)
		}
	}
	return all
}
