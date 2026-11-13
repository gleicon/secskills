package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/probe"
	"github.com/gleicon/secskills/internal/scope"
)

func cmdEnrich(args []string) error {
	fs := flag.NewFlagSet("enrich", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir containing observations.jsonl")
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("usage: secskills enrich --workdir <dir> --confirm")
	}
	obs, err := probe.Load(filepath.Join(*wd, "observations.jsonl"))
	if err != nil {
		return err
	}
	if err := scope.GateNotice("enrich", fmt.Sprintf("%d services in %s", len(obs), *wd), *confirm); err != nil {
		return err
	}
	kev := exposure.LoadKEVForEnrich() // optional, for the name-level cross-reference

	guard := func(u string) error { return probe.SafeURL(u, false) }
	client := probe.NewClient(guard, fetch.UserAgent, false)
	tick := fetch.RateGate()
	defer tick.Stop()

	enriched := make([]exposure.Observation, 0, len(obs))
	for _, o := range obs {
		<-tick.C
		o = exposure.EnrichOne(client, o)
		enriched = append(enriched, o)
	}

	out := filepath.Join(*wd, "enriched-observations.jsonl")
	os.Remove(out)
	store := probe.Store{Path: out}
	for _, o := range enriched {
		store.Append(o)
	}
	exposure.ReportEnrich(enriched, kev, out)
	return nil
}
