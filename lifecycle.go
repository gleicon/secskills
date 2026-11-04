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

// Finding lifecycle (spec FR-7): open -> confirmed -> accepted_risk ->
// fixed (re-verified) -> false_positive. A finding is identified by (ip, cve)
// and persists across runs. Re-verification is a reconcile: re-running the join
// produces a fresh candidate snapshot, and a finding whose candidate has
// disappeared (the product version moved out of the affected range) is closed
// as fixed automatically. accepted_risk and false_positive are human decisions,
// preserved across reconciles.

type LifeFinding struct {
	IP        string `json:"ip"`
	CVE       string `json:"cve"`
	State     string `json:"state"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	FixedAt   string `json:"fixed_at,omitempty"`
	Note      string `json:"note,omitempty"`
}

func (f LifeFinding) key() string { return f.IP + "|" + f.CVE }

// lifeTransitions is the allowed state graph. A self-transition is always a
// no-op and allowed.
var lifeTransitions = map[string]map[string]bool{
	"open":           {"confirmed": true, "accepted_risk": true, "false_positive": true, "fixed": true},
	"confirmed":      {"accepted_risk": true, "false_positive": true, "fixed": true},
	"accepted_risk":  {"fixed": true, "confirmed": true, "open": true},
	"fixed":          {"open": true}, // regression: a fixed finding whose candidate reappears
	"false_positive": {"open": true}, // re-triage
}

// allowedTransition reports whether from->to is a legal lifecycle move.
func allowedTransition(from, to string) bool {
	if from == to {
		return true
	}
	return lifeTransitions[from][to]
}

func loadFindings(path string) map[string]LifeFinding {
	m := map[string]LifeFinding{}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var f LifeFinding
		if jsonUnmarshalLine(ln, &f) {
			m[f.key()] = f
		}
	}
	return m
}

func saveFindings(path string, m map[string]LifeFinding) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tmp := path + ".tmp"
	os.Remove(tmp)
	for _, k := range keys {
		if err := appendJSONL(tmp, m[k]); err != nil {
			return err
		}
	}
	// An empty store still needs the file to exist.
	if len(keys) == 0 {
		os.WriteFile(tmp, nil, 0o644)
	}
	return os.Rename(tmp, path)
}

// reconcile applies the automatic lifecycle transitions for one fresh candidate
// snapshot against the stored findings, returning the updated store and a log of
// what changed. now is the timestamp to stamp.
func reconcile(stored map[string]LifeFinding, current []intel.Candidate, now string) (map[string]LifeFinding, []string) {
	out := map[string]LifeFinding{}
	for k, v := range stored {
		out[k] = v
	}
	var log []string

	present := map[string]intel.Candidate{}
	for _, c := range current {
		present[c.AssetIP+"|"+c.CVE] = c
	}

	// Candidates present now.
	for key, c := range present {
		f, ok := out[key]
		if !ok {
			out[key] = LifeFinding{IP: c.AssetIP, CVE: c.CVE, State: "open", FirstSeen: now, LastSeen: now}
			log = append(log, "OPEN      "+key)
			continue
		}
		f.LastSeen = now
		switch f.State {
		case "fixed":
			f.State, f.FixedAt = "open", ""
			f.Note = "regressed: candidate reappeared"
			log = append(log, "REGRESSED "+key)
		case "false_positive":
			// a confirmed false positive is not auto-reopened
		}
		out[key] = f
	}

	// Findings whose candidate has disappeared → re-verified fixed.
	for key, f := range out {
		if _, still := present[key]; still {
			continue
		}
		switch f.State {
		case "open", "confirmed", "accepted_risk":
			f.State, f.FixedAt, f.LastSeen = "fixed", now, now
			f.Note = "re-verified: candidate no longer matches (version moved out of range)"
			out[key] = f
			log = append(log, "FIXED     "+key)
		}
	}
	return out, log
}

func cmdLifecycle(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills lifecycle <reconcile|set> --workdir <dir> ...")
	}
	fs := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir with candidates.jsonl")
	ip := fs.String("ip", "", "set: finding IP")
	cve := fs.String("cve", "", "set: finding CVE")
	state := fs.String("state", "", "set: target state (confirmed|accepted_risk|false_positive)")
	note := fs.String("note", "", "set: optional note")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("--workdir is required")
	}
	storePath := filepath.Join(*wd, "findings.jsonl")
	store := loadFindings(storePath)

	switch args[0] {
	case "reconcile":
		cands := loadCandidates(filepath.Join(*wd, "candidates.jsonl"))
		updated, log := reconcile(store, cands, nowRFC())
		if err := saveFindings(storePath, updated); err != nil {
			return err
		}
		counts := map[string]int{}
		for _, f := range updated {
			counts[f.State]++
		}
		fmt.Printf("lifecycle reconcile: %d findings tracked -> %s\n", len(updated), storePath)
		fmt.Printf("  states: %v\n", counts)
		for _, l := range log {
			fmt.Println("  " + l)
		}
		return nil
	case "set":
		if *ip == "" || *cve == "" || *state == "" {
			return fmt.Errorf("set requires --ip --cve --state")
		}
		key := *ip + "|" + *cve
		f, ok := store[key]
		if !ok {
			return fmt.Errorf("no finding %s", key)
		}
		if !allowedTransition(f.State, *state) {
			return fmt.Errorf("illegal transition %s -> %s for %s", f.State, *state, key)
		}
		f.State, f.LastSeen = *state, nowRFC()
		if *note != "" {
			f.Note = *note
		}
		store[key] = f
		if err := saveFindings(storePath, store); err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", key, *state)
		return nil
	default:
		return fmt.Errorf("unknown lifecycle subcommand %q (want reconcile|set)", args[0])
	}
}
