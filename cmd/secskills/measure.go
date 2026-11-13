package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/textutil"
)

// cmdMeasure prints the detector quality scorecard for the local corpus.
func cmdMeasure(args []string) error {
	_ = args // no flags: the corpus is fixed
	netsec.AllowLocalProbes = true
	defer func() { netsec.AllowLocalProbes = false }()
	wd, _ := os.MkdirTemp("", "sk-measure")
	defer os.RemoveAll(wd)
	scores, mism := engine.RunMeasureCorpus(wd)

	dets := make([]string, 0, len(scores))
	for k := range scores {
		dets = append(dets, k)
	}
	sort.Strings(dets)
	out := map[string]any{}
	fmt.Println("Engine self-measurement (local corpus of vulnerable + safe servers)")
	fmt.Println("| Detector | TP | FP | FN | TN | Precision | Recall |")
	fmt.Println("|----------|---:|---:|---:|---:|----------:|-------:|")
	allPass := true
	for _, d := range dets {
		s := scores[d]
		prec := textutil.Ratio(s.TP, s.TP+s.FP)
		rec := textutil.Ratio(s.TP, s.TP+s.FN)
		fmt.Printf("| %s | %d | %d | %d | %d | %.0f%% | %.0f%% |\n", d, s.TP, s.FP, s.FN, s.TN, prec*100, rec*100)
		out[d] = map[string]any{"tp": s.TP, "fp": s.FP, "fn": s.FN, "tn": s.TN, "precision": prec, "recall": rec}
		if s.FP > 0 || s.FN > 0 {
			allPass = false
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	os.WriteFile("measure-report.json", b, 0o644)
	if len(mism) > 0 {
		fmt.Println("\nMismatches:")
		for _, m := range mism {
			fmt.Println("  - " + m)
		}
	}
	var TP, FP, FN, TN int
	for _, sc := range scores {
		TP, FP, FN, TN = TP+sc.TP, FP+sc.FP, FN+sc.FN, TN+sc.TN
	}
	fmt.Printf("\nAggregate: precision %.0f%% recall %.0f%% across %d detector families; %d corpus checks (TP=%d FP=%d FN=%d TN=%d).\n",
		textutil.Ratio(TP, TP+FP)*100, textutil.Ratio(TP, TP+FN)*100, len(scores), TP+FP+FN+TN, TP, FP, FN, TN)
	fmt.Printf("Negative-control cases (deceptive 200, WAF challenge, private 403, decoy secret) enforced.\n")
	fmt.Printf("\nScorecard -> measure-report.json. Result: %s\n", engine.PassLabel(allPass && len(mism) == 0))
	if !allPass || len(mism) > 0 {
		os.Exit(1)
	}
	return nil
}
