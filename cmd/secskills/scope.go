package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/scope"
	"github.com/gleicon/secskills/internal/textutil"
)

func cmdScope(args []string) error {
	fs := flag.NewFlagSet("scope", flag.ContinueOnError)
	initT := fs.Bool("init", false, "write a template .secskills-scope.yml")
	validate := fs.Bool("validate", false, "validate the scope file and show what it authorizes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := ".secskills-scope.yml"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	if *initT {
		if textutil.FileExists(path) {
			return fmt.Errorf("%s already exists — edit it or remove it first", path)
		}
		tmpl := `# secskills engagement scope — written by intake, honored by the authorization gate
engagement: <name>
authorized: false          # set true ONLY with written authorization from the target owner
engagement_type: black-box # black-box | grey-box | white-box
confirmed_by: <you@org>
expires: ` + time.Now().Add(720*time.Hour).Format(time.RFC3339) + `
intrusive: false           # true requires a second explicit confirmation at test time
targets:
  - <apex-domain>
out_of_scope:
  - <host-to-exclude>
`
		if err := os.WriteFile(path, []byte(tmpl), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s — edit it, set authorized: true after you have written authorization.\n", path)
		return nil
	}
	if *validate || true {
		s, err := scope.LoadScopeFile(path)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", path, err)
		}
		fmt.Printf("scope file: %s\n", path)
		fmt.Printf("  authorized: %v · type: %s · intrusive: %v\n", s.Authorized, s.Type, s.Intrusive)
		if !s.Expires.IsZero() {
			exp := "valid"
			if time.Now().After(s.Expires) {
				exp = "EXPIRED"
			}
			fmt.Printf("  expires: %s (%s)\n", s.Expires.Format(time.RFC3339), exp)
		}
		fmt.Printf("  targets: %s\n", strings.Join(s.Targets, ", "))
		if len(s.OutOfScope) > 0 {
			fmt.Printf("  out_of_scope: %s\n", strings.Join(s.OutOfScope, ", "))
		}
		if !s.Authorized {
			fmt.Println("  RESULT: NOT authorized — discover/test will require --confirm until authorized: true.")
		} else {
			fmt.Println("  RESULT: authorized — listed targets pass the gate without --confirm.")
		}
	}
	return nil
}
