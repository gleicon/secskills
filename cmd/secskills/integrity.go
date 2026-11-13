package main

import (
	"flag"
	"fmt"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/jsonl"
	"github.com/gleicon/secskills/internal/scope"
	"github.com/gleicon/secskills/internal/workspace"
)

func cmdIntegrity(args []string) error {
	fs := flag.NewFlagSet("integrity", flag.ContinueOnError)
	store := fs.String("store", "./integrity-baselines.jsonl", "append-only baseline ledger")
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	rest, err := workspace.ParseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) < 2 {
		return fmt.Errorf("usage: secskills integrity [--store file] <snapshot|verify> <url> --confirm")
	}
	op, url := rest[0], rest[1]
	// Both operations send live traffic to the target: same gate as test.
	if err := scope.GateNotice("integrity "+op, url, *confirm); err != nil {
		return err
	}
	switch op {
	case "snapshot":
		sum, err := engine.IntegrityBaseline(url)
		if err != nil {
			return err
		}
		rec := engine.IntegrityRecord{URL: url, SHA256: sum, Time: finding.NowRFC()}
		if err := jsonl.AppendJSONL(*store, rec); err != nil {
			return fmt.Errorf("write baseline: %w", err)
		}
		fmt.Printf("baseline %s  %s -> %s\n", sum, url, *store)
		return nil
	case "verify":
		rec, ok := engine.LoadIntegrityBaseline(*store, url)
		if !ok {
			return fmt.Errorf("no baseline for %s in %s — snapshot first", url, *store)
		}
		sum, _, ok := engine.ResponseDigest(url)
		if !ok {
			return fmt.Errorf("INCONCLUSIVE: unreachable: %s", url)
		}
		if sum == rec.SHA256 {
			fmt.Printf("OK: response matches integrity baseline (%s)\n", sum)
			return nil
		}
		return fmt.Errorf("DRIFT: baseline %s, observed %s — possible intermediary rewrite", rec.SHA256, sum)
	default:
		return fmt.Errorf("unknown integrity op %q (snapshot|verify)", op)
	}
}
