package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gleicon/secskills/internal/intel"
)

// Precision gate (spec AC-4): before any customer sees a feed, precision against
// a hand-labelled set of >=100 hosts must be >= 90%, and both the corpus and the
// measurement must be committed. This command is the measurement: it joins a
// ground-truth label set against the candidates the pipeline produced and prints
// precision/recall with a PASS/FAIL verdict. The label corpus is operator-
// supplied (who labels is spec open-Q4); `testdata/precision/labels.example.jsonl`
// documents the schema.
//
// A label is one (ip, cve, label) row where label is "vuln" (the host really is
// affected) or "safe" (it is not — e.g. a backport fixed it behind an unchanged
// version string, the D-9 case). Scoring per (ip, cve):
//
//	label=vuln, candidate present -> TP      label=vuln, absent -> FN
//	label=safe, candidate present -> FP      label=safe, absent -> TN
//
// precision = TP/(TP+FP), recall = TP/(TP+FN). The gate is on precision: a false
// positive shown to a customer is the expensive error, so FP is what AC-4 bounds.
type precisionLabel struct {
	IP    string `json:"ip"`
	CVE   string `json:"cve"`
	Label string `json:"label"` // vuln | safe
}

func loadPrecisionLabels(path string) ([]precisionLabel, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []precisionLabel
	for n, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" || strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		var l precisionLabel
		if !jsonUnmarshalLine(ln, &l) {
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

// scorePrecision is the pure join, split out so the test exercises it without
// files. hosts is the count of distinct IPs in the label set.
func scorePrecision(labels []precisionLabel, cands []intel.Candidate) (tp, fp, fn, tn, hosts int) {
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

	labels, err := loadPrecisionLabels(*labelsPath)
	if err != nil {
		return fmt.Errorf("labels: %w", err)
	}
	if len(labels) == 0 {
		return fmt.Errorf("no labels in %s", *labelsPath)
	}
	cands := loadCandidates(cp)

	tp, fp, fn, tn, hosts := scorePrecision(labels, cands)
	prec := ratio(tp, tp+fp)
	rec := ratio(tp, tp+fn)

	fmt.Printf("precision gate (AC-4) — %s\n", cp)
	fmt.Printf("  labels: %d over %d distinct hosts\n", len(labels), hosts)
	fmt.Println("  TP   FP   FN   TN")
	fmt.Printf("  %-4d %-4d %-4d %-4d\n", tp, fp, fn, tn)
	fmt.Printf("  precision %.1f%%   recall %.1f%%\n", prec*100, rec*100)

	// False positives are what a customer would see wrongly — name them so the
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
