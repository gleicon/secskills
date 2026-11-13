// Command secskills is a single-binary security assessment orchestrator.
//
// It is the portable core shared by every agent adapter (Claude Code SKILL.md,
// opencode command, and the built-in MCP stdio server): all logic lives here,
// no LLM required. External pentest tools (nuclei, httpx, ast-grep, …) are
// shelled out to, never reimplemented; the OWASP knowledge base and ast-grep
// rules are embedded (see the root package, assets.go).
//
// Install:
//
//	go install github.com/gleicon/secskills/cmd/secskills@latest
package main

import (
	"fmt"
	"os"

	"github.com/gleicon/secskills"
)

func usage() {
	fmt.Fprint(os.Stderr, `secskills `+secskills.Version+` — security assessment orchestrator

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
  test        OWASP Top 10 active tests against a surface (authorization-gated; --profile passive|safe-active|adversarial-readonly|authorized-exploit)
  sandbox     Build/run an artifact isolated in Docker, then test it
  report      Assemble report (--render|--html|--pdf|--audit) / --retest a prior run
  tickets     Export findings as ticket rows (CSV/JSON) — fields = ticket fields
  export      Export findings as SARIF 2.1.0 or CycloneDX 1.5 + VEX (interop)
  compress    Shrink text via tldt (token hygiene)
  scrub       Redact PII/secrets via tldt (for reports)
  scan        Detect prompt-injection + PII in untrusted output
  findings    Manage the findings store (add | write-run | list | show)
  profile     Passive pre-engagement OSINT brief (no target traffic) — feeds the intake
  scope       Write/validate the engagement scope file (.secskills-scope.yml)
  override    Record an auditable severity adjudication (reviewed vs automated)
  attest      Sign (--sign) / verify (--verify) a run's attestation (ed25519)
  conformance Detector quality scorecard from the offline regression corpus
  measure     Engine self-measurement against a local vulnerable+safe corpus (precision/recall)
  oast-server Run a self-hostable OAST collaborator (HTTP callback listener + /poll) for blind-SSRF validation
  integrity   Snapshot/verify sha256 response baselines (AC-1 intermediary-rewrite detection)
  fp          Technology fingerprint registry (list | add | import) — grows like Wappalyzer/Shodan
  shodan      Shodan lookup for a domain/IP (software, ports, ASN) when key present
  mcp         Run as an MCP stdio server (tools: doctor, kb, fetch, source)
  watch       Continuous mode: re-assess on an interval, report posture drift (NEW/FIXED/REGRESSED)
  selftest    End-to-end pipeline test against a local disposable server
  version     Print version

EXPOSURE (ASN/CIDR blocks — see docs/exposure.md):
  discover    --asn AS… | --cidr …  sweep a block into observations (authorization-gated)
  enrich      Banner/version/CPE enrichment of stored observations (authorization-gated)
  leakcheck   Read-only check for exposed .git/.env, listings, open datastores (authorization-gated)
  dbcheck     Datastore open/default-credential posture (needs --confirm and --intrusive-confirm)
  kprobe      Single-packet kernel-path reachability probe: MPTCP, IPv4 options (authorization-gated)
  feed        Fetch and cache KEV, EPSS and NVD intelligence (no target traffic)
  cvematch    Join enriched observations with cached NVD ranges into ranked CVE candidates (offline)
  lifecycle   Reconcile or set finding states: open, confirmed, accepted_risk, fixed, false_positive
  prefix-report Markdown exposure report for a block (offline)
  precision   Measure candidate precision against a labelled set (release gate)
  deliver     Write one tenant's feed, optionally POSTed to an HTTPS webhook
  notify      Check event-to-notification latency against stored candidates (offline)
  fleet       Anonymised cross-tenant ranking of CVEs and stacks (k-anonymity)
  plan        Split an ASN's prefixes across N capture workers (OSINT only)
  token       Sign or verify an HMAC scope token for unattended workers
  match       Replay the deterministic matcher on a fixture (advisory x distro state x assets)

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
	case "match":
		err = cmdMatch(args)
	case "leakcheck":
		err = cmdLeakcheck(args)
	case "prefix-report":
		err = cmdPrefixReport(args)
	case "feed":
		err = cmdFeed(args)
	case "dbcheck":
		err = cmdDBCheck(args)
	case "enrich":
		err = cmdEnrich(args)
	case "cvematch":
		err = cmdCVEMatch(args)
	case "token":
		err = cmdToken(args)
	case "lifecycle":
		err = cmdLifecycle(args)
	case "kprobe":
		err = cmdKProbe(args)
	case "plan":
		err = cmdPlan(args)
	case "precision":
		err = cmdPrecision(args)
	case "deliver":
		err = cmdDeliver(args)
	case "notify":
		err = cmdNotify(args)
	case "fleet":
		err = cmdFleet(args)
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
	case "override":
		err = cmdOverride(args)
	case "attest":
		err = cmdAttest(args)
	case "conformance":
		err = cmdConformance(args)
	case "fp":
		err = cmdFP(args)
	case "measure":
		err = cmdMeasure(args)
	case "oast-server":
		err = cmdOASTServer(args)
	case "integrity":
		err = cmdIntegrity(args)
	case "export":
		err = cmdExport(args)
	case "watch":
		err = cmdWatch(args)
	case "mcp":
		err = cmdMCP(args)
	case "version", "-v", "--version":
		fmt.Println("secskills", secskills.Version)
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
