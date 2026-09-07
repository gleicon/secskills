// Command secskills is a single-binary security assessment orchestrator.
//
// It is the portable core shared by every agent adapter (Claude Code SKILL.md,
// opencode command, and the built-in MCP stdio server): all logic lives here,
// no LLM required. External pentest tools (nuclei, httpx, ast-grep, …) are
// shelled out to, never reimplemented; the OWASP knowledge base and ast-grep
// rules are embedded (see embed.go).
package main

import (
	"fmt"
	"os"
)

const version = "0.11.0"

func usage() {
	fmt.Fprint(os.Stderr, `secskills `+version+` — security assessment orchestrator

USAGE:
  secskills <command> [args]

COMMANDS:
  doctor      Check tools present/missing per mode+category, print install commands
  fetch       Throttled GET of a free data source (per-source backoff + Retry-After)
  post        Throttled POST (e.g. OSV batch query)
  kb          Serve the embedded OWASP knowledge base (list | <class> | top10)
  recipes     Serve per-stack secure/vulnerable recipes (Node/Python/Go)
  source      Static source review — run embedded ast-grep rules over a path
  discover    Live attack-surface discovery (authorization-gated)
  graph       Cross-domain exploration graph (OSINT pivots; discovered domains NOT tested)
  test        OWASP Top 10 active tests against a surface (authorization-gated)
  sandbox     Build/run an artifact isolated in Docker, then test it
  report      Assemble findings report / --retest a prior run
  tickets     Export findings as ticket rows (CSV/JSON) — fields = ticket fields
  compress    Shrink text via tldt (token hygiene)
  scrub       Redact PII/secrets via tldt (for reports)
  scan        Detect prompt-injection + PII in untrusted output
  findings    Manage the findings store (add | write-run | list | show)
  profile     Passive pre-engagement OSINT brief (no target traffic) — feeds the intake
  scope       Write/validate the engagement scope file (.secskills-scope.yml)
  shodan      Shodan lookup for a domain/IP (software, ports, ASN) when key present
  mcp         Run as an MCP stdio server (tools: doctor, kb, fetch, source)
  selftest    End-to-end pipeline test against a local disposable server
  version     Print version

Run "secskills <command> -h" for command flags. Portable across Claude Code,
opencode, and any MCP client.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "doctor":
		err = cmdDoctor(args)
	case "fetch":
		err = cmdFetch(args, false)
	case "post":
		err = cmdFetch(args, true)
	case "kb":
		err = cmdKB(args)
	case "recipes":
		err = cmdRecipes(args)
	case "source":
		err = cmdSource(args)
	case "discover":
		err = cmdDiscover(args)
	case "graph":
		err = cmdGraph(args)
	case "test":
		err = cmdTest(args)
	case "sandbox":
		err = cmdSandbox(args)
	case "report":
		err = cmdReport(args)
	case "tickets":
		err = cmdTickets(args)
	case "findings":
		err = cmdFindings(args)
	case "selftest":
		err = cmdSelftest(args)
	case "compress":
		err = cmdTLDT(args, "compress")
	case "scrub":
		err = cmdTLDT(args, "scrub")
	case "scan":
		err = cmdTLDT(args, "scan")
	case "shodan":
		err = cmdShodan(args)
	case "profile":
		err = cmdProfile(args)
	case "scope":
		err = cmdScope(args)
	case "mcp":
		err = cmdMCP(args)
	case "version", "-v", "--version":
		fmt.Println("secskills", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
