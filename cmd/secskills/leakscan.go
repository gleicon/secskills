package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/jsonl"
	"github.com/gleicon/secskills/internal/probe"
	"github.com/gleicon/secskills/internal/scope"
)

func cmdLeakcheck(args []string) error {
	fs := flag.NewFlagSet("leakcheck", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir containing observations.jsonl (required)")
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("usage: secskills leakcheck --workdir <dir> --confirm")
	}
	obs, err := probe.Load(filepath.Join(*wd, "observations.jsonl"))
	if err != nil {
		return fmt.Errorf("load observations: %w", err)
	}
	if len(obs) == 0 {
		return fmt.Errorf("no observations in %s", *wd)
	}
	// One gate for the whole set: these are active (read-only) requests.
	if err := scope.GateNotice("leakcheck", fmt.Sprintf("%d services in %s", len(obs), *wd), *confirm); err != nil {
		return err
	}

	guard := func(u string) error { return probe.SafeURL(u, false) }
	client := probe.NewClient(guard, fetch.UserAgent, false)
	tick := fetch.RateGate()
	defer tick.Stop()

	var findings []exposure.LeakFinding
	for _, o := range obs {
		<-tick.C
		switch o.Service {
		case "http", "https":
			findings = append(findings, exposure.HTTPLeaks(client, tick.C, o)...)
		case "elasticsearch":
			if f, ok := exposure.EsOpenIndices(client, o); ok {
				findings = append(findings, f)
			}
		case "redis":
			if ok, ev := exposure.RedisUnauth(net.JoinHostPort(o.IP, fmt.Sprint(o.Port))); ok {
				findings = append(findings, exposure.LeakFinding{IP: o.IP, Port: o.Port, Kind: "redis-unauth", Evidence: ev})
			}
		}
	}

	out := filepath.Join(*wd, "leaks.jsonl")
	os.Remove(out)
	for _, f := range findings {
		if err := jsonl.AppendJSONL(out, f); err != nil {
			return err
		}
	}
	exposure.ReportLeaks(findings, out)
	return nil
}
