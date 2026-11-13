package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/finding"
)

var verRe = regexp.MustCompile(`([A-Za-z][A-Za-z0-9_-]+)/(\d+\.\d+(?:\.\d+)?)`)

// osvEcosystem maps a server product name to an OSV ecosystem+package.
func osvEcosystem(name string) (pkg, eco string) {
	switch strings.ToLower(name) {
	case "nginx":
		return "nginx", "Debian"
	case "apache", "httpd":
		return "apache-httpd", "OSS-Fuzz"
	case "gunicorn":
		return "gunicorn", "PyPI"
	case "openresty":
		return "nginx", "Debian"
	case "lighttpd":
		return "lighttpd", "Debian"
	default:
		return "", ""
	}
}

// osvVuln is the subset of an OSV record we use for precision filtering.
type osvVuln struct {
	ID       string `json:"id"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// fixedAfter reports whether the vuln has a fixed version strictly greater than
// ver (i.e. our version is genuinely unpatched for it). If no range data exists,
// returns ok=false so the caller can treat it as low-confidence.
func fixedAfter(v osvVuln, ver string) (unpatched, hasRange bool) {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if fx, ok := e["fixed"]; ok {
					hasRange = true
					if semverLess(ver, fx) {
						unpatched = true
					}
				}
			}
		}
	}
	return
}

// semverLess compares dotted numeric versions (a < b). Non-numeric parts ignored.
func semverLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var ai, bi int
		if i < len(as) {
			fmt.Sscanf(as[i], "%d", &ai)
		}
		if i < len(bs) {
			fmt.Sscanf(bs[i], "%d", &bi)
		}
		if ai != bi {
			return ai < bi
		}
	}
	return false
}

// CVELookup parses a Server header, queries OSV (throttled), and returns a
// component finding (A06). Precision: prefer CVEs that are genuinely unpatched
// for the detected version (fixed range > version) and rank severity by CVSS.
func CVELookup(host, serverHeader string) *finding.Finding {
	m := verRe.FindStringSubmatch(serverHeader)
	if m == nil {
		return nil
	}
	name, ver := m[1], m[2]
	pkg, eco := osvEcosystem(name)
	if pkg == "" {
		return nil
	}
	body, err := fetch.HTTPDo("osv", "POST", "https://api.osv.dev/v1/query",
		fmt.Sprintf(`{"version":%q,"package":{"name":%q,"ecosystem":%q}}`, ver, pkg, eco), 3)
	if err != nil {
		return nil
	}
	var r struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Vulns) == 0 {
		return nil
	}

	// partition: unpatched (fixed>ver) vs range-less (low confidence)
	var unpatched, unranged []string
	maxSev := 0 // 0 none,1 low,2 med,3 high,4 crit
	sevRank := map[string]int{"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for _, v := range r.Vulns {
		up, hasRange := fixedAfter(v, ver)
		if s := sevRank[strings.ToUpper(v.DatabaseSpecific.Severity)]; s > maxSev {
			maxSev = s
		}
		switch {
		case up:
			unpatched = append(unpatched, v.ID)
		case !hasRange:
			unranged = append(unranged, v.ID)
		}
	}
	// If range data existed and none are unpatched, our version is patched → skip.
	if len(unpatched) == 0 && len(unranged) == 0 {
		return nil
	}

	count := len(unpatched)
	ids := unpatched
	if count == 0 { // only range-less matches — lower confidence
		count = len(unranged)
		ids = unranged
	}
	// Version→CVE correlation is a LEAD, not a demonstrated vulnerability: the
	// version is banner-inferred, distro backports keep upstream-looking versions,
	// the OS/build/config/modules are unknown, and exploitability is not proven.
	// Cap at MEDIUM and mark low confidence + manual-validation-required. Only a
	// safe validation of an actual applicable CVE against the host justifies HIGH.
	sev := "MEDIUM"
	if count <= 5 && len(unpatched) == 0 {
		sev = "LOW"
	}
	if len(ids) > 10 {
		ids = ids[:10]
	}
	f := &finding.Finding{
		Title:      fmt.Sprintf("Potentially vulnerable %s version %s — manual validation required (%d CVEs correlate via OSV)", name, ver, count),
		Host:       host,
		Severity:   sev,
		Status:     "open",
		Confidence: "Low",
		Validation: "version-inferred",
		ImpactText: fmt.Sprintf("The %s version is inferred from the Server banner. OSV lists %d CVEs for %s/%s in the %s ecosystem, but this does NOT establish that the host runs the vulnerable build/config or that any CVE is remotely exploitable here (backported distro patches keep the same upstream version). Treat as a lead for manual validation, not a confirmed vulnerability.",
			name, count, name, ver, eco),
		EvidenceCmd:  fmt.Sprintf(`curl -s -X POST https://api.osv.dev/v1/query -d '{"version":"%s","package":{"name":"%s","ecosystem":"%s"}}' | jq '[.vulns[]|select(.affected[].ranges[].events[].fixed)]|length'`, ver, pkg, eco),
		ExpectedOpen: "",
		CVEs:         ids,
		ProbeKind:    "manual",
	}
	finding.Classify(f)
	// override remediation reference: upgrading is the fix; hiding the banner is NOT.
	f.References = append(f.References, "Remediation: upgrade the component to a fixed release and confirm the running build. Hiding the version banner is fingerprint-reduction, NOT remediation.")
	return f
}

// osvQuery queries OSV for a package@version and returns affecting advisory IDs
// plus the max severity rank (0..4). Used by the runtime planner's CVE-
// applicability probe. Best-effort; empty on any failure.
func osvQuery(pkg, eco, ver string) ([]string, int) {
	body, err := fetch.HTTPDo("osv", "POST", "https://api.osv.dev/v1/query",
		fmt.Sprintf(`{"version":%q,"package":{"name":%q,"ecosystem":%q}}`, ver, pkg, eco), 3)
	if err != nil {
		return nil, 0
	}
	var r struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Vulns) == 0 {
		return nil, 0
	}
	sevRank := map[string]int{"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	var ids []string
	maxSev := 0
	for _, v := range r.Vulns {
		if up, _ := fixedAfter(v, ver); up {
			ids = append(ids, v.ID)
			if s := sevRank[strings.ToUpper(v.DatabaseSpecific.Severity)]; s > maxSev {
				maxSev = s
			}
		}
	}
	return ids, maxSev
}
