package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/gleicon/secskills/internal/engine"
)

// cmdConformance runs the corpus and prints the detector quality scorecard.
func cmdConformance(args []string) error {
	fs := flag.NewFlagSet("conformance", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit machine-readable scorecard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scores, mismatches := engine.RunConformance()
	fams := make([]string, 0, len(scores))
	for k := range scores {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	if *asJSON {
		out := map[string]any{}
		for _, f := range fams {
			out[f] = map[string]any{"tp": scores[f].TP, "fp": scores[f].FP, "fn": scores[f].FN,
				"precision": engine.Precision(scores[f]), "recall": engine.Recall(scores[f])}
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	fmt.Println("Detector quality scorecard (offline regression corpus)")
	fmt.Println("| Detector family | TP | FP | FN | Precision | Recall |")
	fmt.Println("|-----------------|---:|---:|---:|----------:|-------:|")
	for _, f := range fams {
		s := scores[f]
		fmt.Printf("| %s | %d | %d | %d | %.0f%% | %.0f%% |\n", f, s.TP, s.FP, s.FN, engine.Precision(s)*100, engine.Recall(s)*100)
	}
	if len(mismatches) > 0 {
		fmt.Println("\nMismatches:")
		for _, m := range mismatches {
			fmt.Println("  - " + m)
		}
		os.Exit(1)
	}
	return nil
}
