package exposure

import (
	"fmt"
	"os"
	"strings"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/jsonl"
)

// Precision gate (spec AC-4): before any feed is delivered, precision against
// a hand-labelled set of >=100 hosts must be >= 90%, and both the corpus and the
// measurement must be committed. This command is the measurement: it joins a
// ground-truth label set against the candidates the pipeline produced and prints
// precision/recall with a PASS/FAIL verdict. The label corpus is supplied by
// the operator; `testdata/precision/labels.example.jsonl` documents the schema.
//
// A label is one (ip, cve, label) row where label is "vuln" (the host really is
// affected) or "safe" (it is not — e.g. a backport fixed it behind an unchanged
// version string, the D-9 case). Scoring per (ip, cve):
//
//	label=vuln, candidate present -> TP      label=vuln, absent -> FN
//	label=safe, candidate present -> FP      label=safe, absent -> TN
//
// precision = TP/(TP+FP), recall = TP/(TP+FN). The gate is on precision: a false
// positive in a delivered feed is the expensive error, so FP is what AC-4 bounds.
type PrecisionLabel struct {
	IP    string `json:"ip"`
	CVE   string `json:"cve"`
	Label string `json:"label"` // vuln | safe
}

// LoadPrecisionLabels reads a ground-truth label set (JSONL {ip,cve,label}).
func LoadPrecisionLabels(path string) ([]PrecisionLabel, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []PrecisionLabel
	for n, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" || strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		var l PrecisionLabel
		if !jsonl.JSONUnmarshalLine(ln, &l) {
			return nil, fmt.Errorf("line %d: not valid JSON", n+1)
		}
		if l.IP == "" || l.CVE == "" {
			return nil, fmt.Errorf("line %d: ip and cve are required", n+1)
		}
		if l.Label != "vuln" && l.Label != "safe" {
			return nil, fmt.Errorf("line %d: label must be \"vuln\" or \"safe\", got %q", n+1, l.Label)
		}
		out = append(out, l)
	}
	return out, nil
}

// ScorePrecision is the pure join, split out so the test exercises it without
// files. hosts is the count of distinct IPs in the label set.
func ScorePrecision(labels []PrecisionLabel, cands []intel.Candidate) (tp, fp, fn, tn, hosts int) {
	present := map[string]bool{}
	for _, c := range cands {
		present[c.AssetIP+"|"+c.CVE] = true
	}
	ips := map[string]bool{}
	for _, l := range labels {
		ips[l.IP] = true
		has := present[l.IP+"|"+l.CVE]
		switch {
		case l.Label == "vuln" && has:
			tp++
		case l.Label == "vuln" && !has:
			fn++
		case l.Label == "safe" && has:
			fp++
		default:
			tn++
		}
	}
	return tp, fp, fn, tn, len(ips)
}
