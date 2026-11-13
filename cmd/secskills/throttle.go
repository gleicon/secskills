package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gleicon/secskills/internal/fetch"
)

func cmdFetch(args []string, post bool) error {
	name := "fetch"
	if post {
		name = "post"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	retries := fs.Int("retries", 4, "max retries on 429/503/timeout")
	// Flags must precede positionals (Go flag semantics); tolerate leading flags.
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	method := "GET"
	minArgs := 2
	if post {
		method = "POST"
		minArgs = 3
	}
	if len(rest) < minArgs {
		if post {
			return fmt.Errorf("usage: secskills post <source> <url> <json-body>")
		}
		return fmt.Errorf("usage: secskills fetch <source> <url>")
	}
	source, url := rest[0], rest[1]
	body := ""
	if post {
		body = rest[2]
	}
	out, err := fetch.HTTPDo(source, method, url, body, *retries)
	if err != nil {
		return err
	}
	os.Stdout.Write(out)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		fmt.Println()
	}
	return nil
}
