package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills/internal/exposure"
	"github.com/gleicon/secskills/internal/jsonl"
	"github.com/gleicon/secskills/internal/probe"
)

func cmdDBCheck(args []string) error {
	fs := flag.NewFlagSet("dbcheck", flag.ContinueOnError)
	wd := fs.String("workdir", "", "workdir containing observations.jsonl")
	confirm := fs.Bool("confirm", false, "authorization confirmed")
	intrusive := fs.Bool("intrusive-confirm", false, "second confirmation: permit default-credential attempts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *wd == "" {
		return fmt.Errorf("usage: secskills dbcheck --workdir <dir> --confirm --intrusive-confirm")
	}
	if !*confirm || !*intrusive {
		return fmt.Errorf("dbcheck makes authentication attempts against hosts; it requires BOTH --confirm and --intrusive-confirm")
	}
	obs, err := probe.Load(filepath.Join(*wd, "observations.jsonl"))
	if err != nil {
		return err
	}
	creds, err := exposure.LoadDefaultCreds()
	if err != nil {
		return err
	}

	var results []exposure.DBResult
	for _, o := range obs {
		if !exposure.DatastorePorts[o.Service] || o.Service == "rdp" {
			continue
		}
		addr := net.JoinHostPort(o.IP, fmt.Sprint(o.Port))
		var r exposure.DBResult
		switch o.Service {
		case "redis":
			r = exposure.RedisCheck(addr, creds["redis"])
		case "elasticsearch":
			r = exposure.ESCheck(o.IP, o.Port, creds["elasticsearch"])
		case "mongodb":
			r = exposure.MongoCheck(addr)
		case "mysql":
			r = exposure.MySQLCheck(o.IP, o.Port, creds["mysql"])
		default:
			r = exposure.DBResult{Status: "NOT-TESTED", Detail: "no checker for service"}
		}
		r.IP, r.Port, r.Service = o.IP, o.Port, o.Service
		results = append(results, r)
	}

	out := filepath.Join(*wd, "dbcheck.jsonl")
	os.Remove(out)
	for _, r := range results {
		jsonl.AppendJSONL(out, r)
	}
	exposure.ReportDBCheck(results, out)
	return nil
}
