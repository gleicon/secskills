package main

import (
	"flag"
	"fmt"
	"github.com/gleicon/secskills/internal/exposure"
	"path/filepath"

	"github.com/gleicon/secskills/internal/finding"
)

func cmdFindings(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: secskills findings <add|set|import|write-run|list|show> ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return finding.FindingsAdd(rest)
	case "import":
		return findingsImport(rest)
	case "set":
		return finding.FindingsSet(rest)
	case "write-run":
		return finding.FindingsWriteRun(rest)
	case "list":
		return finding.FindingsList(rest)
	case "show":
		return finding.FindingsShow(rest)
	default:
		return fmt.Errorf("unknown findings subcommand %q", sub)
	}
}

// findingsImport turns a workdir's captured leaks.jsonl and dbcheck.jsonl into
// findings, offline. Use it after merging workdirs from several capture
// machines; leakcheck and dbcheck already do this when run in place.
func findingsImport(args []string) error {
	fs := flag.NewFlagSet("findings import", flag.ContinueOnError)
	wdFlag := fs.String("workdir", "", "workdir with leaks.jsonl / dbcheck.jsonl (default: the target's workdir)")
	save := fs.Bool("save", true, "save a run for report/retest")
	target, wd, err := blockTarget(fs, args, wdFlag, "secskills findings import <block> [--workdir dir]")
	if err != nil {
		return err
	}
	leaks := exposure.LoadLeaks(filepath.Join(wd, "leaks.jsonl"))
	dbs := exposure.LoadDBChecks(filepath.Join(wd, "dbcheck.jsonl"))
	fmt.Printf("import: %d leak results, %d datastore results from %s\n", len(leaks), len(dbs), wd)
	if _, err := exposure.SyncFindings(wd, exposure.FamilyDB, exposure.DBFindings(dbs)); err != nil {
		return err
	}
	return syncAndSave(target, wd, exposure.FamilyLeak, exposure.LeakFindings(leaks), *save)
}
