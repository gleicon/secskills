package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// M10 — Continuous mode.
// `secskills watch` re-assesses a target on an interval and reports posture
// DRIFT between consecutive runs (NEW / FIXED / REGRESSED / PERSISTING findings),
// keyed by the stable finding_key. Drift is appended to watch-drift.jsonl. This
// turns the one-shot engine into a continuous monitor without external tooling.

type driftEntry struct {
	Time       string         `json:"time"`
	PrevRun    string         `json:"prev_run"`
	CurRun     string         `json:"cur_run"`
	Counts     map[string]int `json:"counts"` // NEW/FIXED/REGRESSED/PERSISTING
	NewKeys    []string       `json:"new_keys,omitempty"`
	FixedKeys  []string       `json:"fixed_keys,omitempty"`
}

func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	interval := fs.Duration("interval", 0, "re-assess every N (e.g. 6h); 0 = run once and exit")
	profile := fs.String("profile", "safe-active", "aggression profile")
	deep := fs.Bool("deep", false, "deep phase each cycle")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fmt.Errorf("usage: secskills watch <target> --confirm [--interval 6h] [--profile ...] [--deep]")
	}
	target := pos[0]
	if err := gateNotice("watch", target, *confirm); err != nil {
		return err
	}
	for {
		cycleStart := time.Now()
		fmt.Printf("== watch cycle @ %s ==\n", cycleStart.UTC().Format(time.RFC3339))
		discArgs := []string{target, "--confirm"}
		testArgs := []string{target, "--confirm", "--profile", *profile}
		if *deep {
			testArgs = append(testArgs, "--deep")
		}
		if err := cmdDiscover(discArgs); err != nil {
			fmt.Fprintln(os.Stderr, "[watch] discover error:", err)
		}
		if err := cmdTest(testArgs); err != nil {
			fmt.Fprintln(os.Stderr, "[watch] test error:", err)
		}
		if d := computeDrift(target); d != nil {
			appendDrift(target, *d)
			fmt.Printf("[watch] drift: NEW=%d FIXED=%d REGRESSED=%d PERSISTING=%d\n",
				d.Counts["NEW"], d.Counts["FIXED"], d.Counts["REGRESSED"], d.Counts["PERSISTING"])
		} else {
			fmt.Println("[watch] baseline established (no prior run to diff)")
		}
		if *interval <= 0 {
			return nil
		}
		next := cycleStart.Add(*interval)
		fmt.Printf("[watch] next cycle at %s (sleeping)\n", next.UTC().Format(time.RFC3339))
		time.Sleep(time.Until(next))
	}
}

// twoLatestRuns returns the two most recent persisted runs for a target.
func twoLatestRuns(target string) (prev, cur *Run) {
	dir := storeDir(target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var files []string
	for _, e := range entries {
		if len(e.Name()) > 4 && e.Name()[:4] == "run-" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	load := func(name string) *Run {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil
		}
		var r Run
		if json.Unmarshal(b, &r) != nil {
			return nil
		}
		return &r
	}
	if len(files) >= 1 {
		cur = load(files[len(files)-1])
	}
	if len(files) >= 2 {
		prev = load(files[len(files)-2])
	}
	return prev, cur
}

// computeDrift diffs the two latest runs by stable finding_key.
func computeDrift(target string) *driftEntry {
	prev, cur := twoLatestRuns(target)
	if prev == nil || cur == nil {
		return nil
	}
	prevKeys := map[string]Finding{}
	for _, f := range prev.Findings {
		prevKeys[f.Key] = f
	}
	curKeys := map[string]Finding{}
	for _, f := range cur.Findings {
		curKeys[f.Key] = f
	}
	d := driftEntry{Time: nowRFC(), PrevRun: prev.RunID, CurRun: cur.RunID, Counts: map[string]int{}}
	for k, cf := range curKeys {
		if _, ok := prevKeys[k]; ok {
			d.Counts["PERSISTING"]++
		} else {
			d.Counts["NEW"]++
			d.NewKeys = append(d.NewKeys, k+" ("+cf.Severity+")")
		}
	}
	for k, pf := range prevKeys {
		if _, ok := curKeys[k]; !ok {
			d.Counts["FIXED"]++
			d.FixedKeys = append(d.FixedKeys, k+" ("+pf.Severity+")")
		}
	}
	sort.Strings(d.NewKeys)
	sort.Strings(d.FixedKeys)
	return &d
}

func appendDrift(target string, d driftEntry) {
	path := filepath.Join(workdir(target), "watch-drift.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(d)
	f.Write(append(b, '\n'))
}
