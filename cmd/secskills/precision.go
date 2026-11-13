package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/textutil"
)

func cmdPrecision(args []string) error {
	fs := flag.NewFlagSet("precision", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with candidates.jsonl")
	labelsPath := fs.String("labels", "", "ground-truth label set (JSONL: {ip,cve,label})")
	candPath := fs.String("candidates", "", "candidates file (default: <workdir>/candidates.jsonl)")
	min := fs.Float64("min", 0.90, "minimum precision to PASS (AC-4 = 0.90)")
	minHosts := fs.Int("min-hosts", 100, "minimum distinct labelled hosts (AC-4 = 100)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *labelsPath == "" {
		return fmt.Errorf("usage: secskills precision --labels labels.jsonl [--workdir dir | --candidates file]")
	}
	cp := *candPath
	if cp == "" {
		if *wd == "" {
			return fmt.Errorf("--candidates or --workdir is required")
		}
		cp = filepath.Join(*wd, "candidates.jsonl")
	}

	labels, err := exposure.LoadPrecisionLabels(*labelsPath)
	if err != nil {
		return fmt.Errorf("labels: %w", err)
	}
	if len(labels) == 0 {
		return fmt.Errorf("no labels in %s", *labelsPath)
	}
	cands := exposure.LoadCandidates(cp)

	tp, fp, fn, tn, hosts := exposure.ScorePrecision(labels, cands)
	prec := textutil.Ratio(tp, tp+fp)
	rec := textutil.Ratio(tp, tp+fn)

	fmt.Printf("precision gate (AC-4) — %s\n", cp)
	fmt.Printf("  labels: %d over %d distinct hosts\n", len(labels), hosts)
	fmt.Println("  TP   FP   FN   TN")
	fmt.Printf("  %-4d %-4d %-4d %-4d\n", tp, fp, fn, tn)
	fmt.Printf("  precision %.1f%%   recall %.1f%%\n", prec*100, rec*100)

	// False positives are what a feed consumer would see wrongly — name them so the
	// gap is actionable, not just a number.
	if fp > 0 {
		present := map[string]bool{}
		for _, c := range cands {
			present[c.AssetIP+"|"+c.CVE] = true
		}
		var fps []string
		for _, l := range labels {
			if l.Label == "safe" && present[l.IP+"|"+l.CVE] {
				fps = append(fps, l.IP+" "+l.CVE)
			}
		}
		sort.Strings(fps)
		fmt.Printf("  false positives (%d):\n", len(fps))
		for _, s := range fps {
			fmt.Println("    " + s)
		}
	}

	var fail []string
	if hosts < *minHosts {
		fail = append(fail, fmt.Sprintf("only %d hosts labelled, AC-4 needs >= %d", hosts, *minHosts))
	}
	if prec < *min {
		fail = append(fail, fmt.Sprintf("precision %.1f%% < %.0f%% gate", prec*100, *min*100))
	}
	if len(fail) > 0 {
		fmt.Printf("VERDICT: FAIL — %s. Not launch-ready; the gap is the next spec item.\n", strings.Join(fail, "; "))
		os.Exit(1)
	}
	fmt.Printf("VERDICT: PASS — precision %.1f%% over %d hosts >= gate.\n", prec*100, hosts)
	return nil
}
