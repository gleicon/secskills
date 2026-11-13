package engine

import (
	"testing"

	"github.com/gleicon/secskills/internal/netsec"
)

// TestEngineMeasurementCorpus is the engine self-measurement gate: every live
// detector must fire on the deliberately-vulnerable corpus server and stay
// silent on the deliberately-safe one, and the negative controls (deceptive
// 200, WAF challenge, private 403 bucket, decoy credential-like metrics) must
// hold. The corpus itself lives in runMeasureCorpus so `secskills measure` and
// this gate can never drift apart. This gate caught a real SSTI product-constant
// bug (the detector would never have fired in production).
func TestEngineMeasurementCorpus(t *testing.T) {
	netsec.AllowLocalProbes = true
	defer func() { netsec.AllowLocalProbes = false }()

	scores, mismatches := RunMeasureCorpus(t.TempDir())
	for _, m := range mismatches {
		t.Errorf("corpus: %s", m)
	}
	if len(scores) == 0 {
		t.Fatal("no detector families were scored")
	}
	for det, s := range scores {
		if s.FP > 0 {
			t.Errorf("%s: %d false positive(s) on the safe corpus", det, s.FP)
		}
		if s.FN > 0 {
			t.Errorf("%s: %d missed detection(s) on the vulnerable corpus", det, s.FN)
		}
	}
}
