package exposure

import (
	"testing"

	"github.com/gleicon/secskills/internal/intel"
	"github.com/gleicon/secskills/internal/textutil"
)

func TestScorePrecision(t *testing.T) {
	labels := []PrecisionLabel{
		{IP: "1.1.1.1", CVE: "CVE-A", Label: "vuln"}, // candidate present -> TP
		{IP: "1.1.1.2", CVE: "CVE-A", Label: "vuln"}, // absent          -> FN
		{IP: "1.1.1.3", CVE: "CVE-B", Label: "safe"}, // present (wrong)  -> FP
		{IP: "1.1.1.4", CVE: "CVE-B", Label: "safe"}, // absent (right)   -> TN
	}
	cands := []intel.Candidate{
		{AssetIP: "1.1.1.1", CVE: "CVE-A"},
		{AssetIP: "1.1.1.3", CVE: "CVE-B"},
	}
	tp, fp, fn, tn, hosts := ScorePrecision(labels, cands)
	if tp != 1 || fp != 1 || fn != 1 || tn != 1 {
		t.Fatalf("tp=%d fp=%d fn=%d tn=%d, want 1/1/1/1", tp, fp, fn, tn)
	}
	if hosts != 4 {
		t.Fatalf("hosts=%d, want 4", hosts)
	}
	if got := textutil.Ratio(tp, tp+fp); got != 0.5 {
		t.Fatalf("precision=%.2f, want 0.50", got)
	}
}

func TestLoadPrecisionLabelsValidates(t *testing.T) {
	if _, err := LoadPrecisionLabels("../../testdata/precision/labels.example.jsonl"); err != nil {
		t.Fatalf("example corpus should parse: %v", err)
	}
}
