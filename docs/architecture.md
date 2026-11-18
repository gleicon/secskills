# Architecture

## One binary, thin adapters

secskills is a single Go binary (one dep: x/net/publicsuffix). All logic lives there — no LLM
required. Agents (Claude Code, opencode, any MCP client) are thin adapters that
call the same CLI. The portable unit across agents is a **CLI**, not any one
agent's skill format.

```
              ┌─────────────────────────────────────────────┐
   Claude Code│ skills/*/SKILL.md  ─┐                        │
   opencode   │ .opencode/command  ─┼──►  secskills <cmd>    │
   MCP client │ secskills mcp      ─┘        (Go binary)     │
              └─────────────────────────────────────────────┘
                                   │
        ┌──────────────┬───────────┼───────────┬──────────────┐
     doctor         profile     discover      test          report
   (tool preflight) (OSINT)   (subfinder→   (checks+OSV+   (md/html/pdf
                               dnsx→httpx)    deep phase)    +compliance)
```

External pentest tools (nuclei, httpx, ast-grep, sslscan, …) are **shelled out
to**, never reimplemented. The OWASP knowledge base, ast-grep rules, recipes, and
the tool registry are **embedded** (`go:embed`) so the binary runs offline.

## Why a binary, not shell

The earlier shell prototype hit portability pain — `shasum` vs `sha256sum`,
`timeout` vs `gtimeout`, BSD vs GNU tools, bash 3.2 vs 5.x. The binary gives one
static artifact (Linux, macOS, Windows), real tests, embedded offline data, and
in-process orchestration (resolve-then-probe, pd-httpx path resolution, temp-file
buffering, backgrounding, rate limits). The shell prototype has been retired; the
skills drive the binary.

## The discover pipeline

`subfinder` (passive) → `dnsx` (concurrent resolve, live only) → `httpx`
(projectdiscovery, minimal flags, temp-file output) → Shodan enrichment. Resolving
first avoids wasting the run on dead names; the binary resolves the projectdiscovery
`httpx` even when Python's `httpx` shadows it on PATH.

## Network mode

For an ASN or CIDR: a rate-limited TCP connect sweep (per-IP authorization, /20
cap) stores observations; `enrich` reads banners; `leakcheck`/`dbcheck` and the
offline `cvematch` join write ordinary findings (`internal/exposure`), so the
same store, report, retest, tickets, and export serve blocks and apps. See
`SPEC-NETWORK.md`.

## The check engine

Native, parallel, rate-limited: security headers, TLS 1.0/1.1 acceptance,
unauthenticated exposure (**baseline-differential** — compared to a random path,
to defeat catch-all 200s), and component CVEs via OSV (filtered to unpatched).
`--deep` adds nuclei (batch), sslscan cipher enumeration, content discovery, and
screenshots. Findings persist **incrementally** so a time-bounded run never loses
partial results.

## Safety model

- **Authorization gate** in the core: every target-touching command (`discover`,
  `test`, `sandbox`, `watch`, `integrity`, `enrich`, `leakcheck`, `dbcheck`)
  refuses without `--confirm` or an authorized `.secskills-scope.yml`.
  `--intrusive` needs a second confirmation. DoS and mass third-party scanning are
  always refused.
- **Offline reporting**: reports, tickets, and exports render from stored
  findings and evidence and never contact the target (pinned by a test).
- **Scope confinement**: every probe checks the confirmed scope; out-of-scope
  hosts are skipped.
- **Untrusted target output**: every target-derived string is run through
  `textutil.NeutralizeUntrusted` (strip invisible/bidi/control unicode, redact injection
  patterns, collapse newlines) before it reaches a finding, report, or stdout;
  injection content is recorded as a finding; tldt adds a second detection layer.
  See `SECURITY.md`.

## Classification

Every finding is mapped to an OWASP category (Web Top 10 2021 / Mobile Top 10 2024
/ LLM Top 10 2025), a CWE, an OWASP Cheat Sheet class, OSV CVEs, an owning team,
and SOC 2 / ISO 27001 / PCI-DSS controls — so the report is both actionable and
audit-usable.

## Source layout

```
cmd/secskills/        the CLI (package main): one file per command — flag
                      parsing and output only; logic lives in internal/
internal/scope/       authorization: scope file, per-IP CIDR filter, the gate
                      notice
internal/netsec/      SSRF guard, shell quoting, host parsing
internal/fetch/       throttled free-source HTTP + non-destructive target client
internal/finding/     finding model, severity policy, detector registry,
                      capabilities, CVSS/OWASP/compliance mapping, evidence
                      ledger, findings store
internal/engine/      discover/test engine: checks, detector packs, adversarial
                      planner, edge mapping, deep scans, conformance + measure
internal/report/      Markdown/HTML/PDF/audit reports, lint, tickets,
                      SARIF/CycloneDX, run attestation
internal/exposure/    network mode (sweep → enrich → leak/db checks → feeds →
                      cvematch); writes ordinary findings via SyncFindings
internal/probe/       embeddable probe layer: Observation store, guarded HTTP
                      (no dependency on the rest)
internal/intel/       NVD version-range matcher
internal/kb/          embedded OWASP KB, recipes, ast-grep rule materializer
internal/tooling/     external tool registry/doctor, httpx/shodan/tldt, Chrome
internal/mcp/         read-only MCP stdio server
internal/workspace/   per-assessment working directory
internal/jsonl/, internal/textutil/   JSON Lines I/O; string helpers and
                      untrusted-output neutralizers
assets.go, version.go root package secskills: go:embed of the data below + Version
kb/, recipes/, data/  embedded knowledge base, recipes, fingerprints, default creds
thirdparty/ast-grep-rules/  embedded ast-grep rules (rules/ is a symlink)
skills/               Claude Code SKILL.md adapters
lib/                  methodology the skills read: authorization gate, OSINT
                      sources, report template
tools/                registry.tsv (embedded tool registry), ingest.sh (KB refresh)
thirdparty/           manual playbooks (redteam-pentest, xss-assist) + ast-grep rules
deploy/               capture kit: setup.sh, capture.sh, process.sh
examples/embed/       using internal/probe as a library
docs/                 reference docs; docs/guides/ task walkthroughs
```

Dependencies point one way: `cmd/secskills` → `report` → `engine` →
`finding` → `kb`/`tooling`/`fetch`/`scope` → `netsec`/`textutil`/`jsonl`.
`exposure` (network mode) sits beside `engine`: it writes ordinary findings into
`finding`, and `report` reads its network inventory. `internal/probe` and
`internal/intel` import nothing else from the module.

## Tests

- `go test ./...` runs unit tests per package plus the **golden CLI suite**
  (`cmd/secskills/cli_golden_test.go`). The suite builds the real binary and runs
  it in a sandbox (temp HOME/TMPDIR/feed cache, whitelisted env, `PATH` with
  only `sh`). Scenarios are chosen so no command contacts a target; report
  rendering is additionally pinned offline by a unit test that forbids every
  outbound connection. It diffs normalized output against
  `cmd/secskills/testdata/golden/`: help and flags of every command, every
  authorization-gate refusal, the KB, MCP, conformance, measure, selftest, a
  network block over `testdata/exposure/`, and the findings →
  report/tickets/SARIF/CycloneDX/attest path.
- It is black-box, so it holds across refactors. After an **intended** output
  change, regenerate and review the diff:
  `go test ./cmd/secskills -run TestGolden -update && git diff cmd/secskills/testdata/golden`.
- Coverage of the black-box suite:
  `SECSKILLS_GOLDEN_COVER=1 GOCOVERDIR=$(mktemp -d) go test ./cmd/secskills -run TestGolden`
  then `go tool covdata percent -i <dir>`.
- CI (`.github/workflows/ci.yml`): gofmt, vet, race tests, staticcheck,
  `go install`, cross-compile for linux/darwin/windows.
