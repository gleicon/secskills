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
static artifact (mac/linux/arm), real tests, embedded offline data, and
in-process orchestration (resolve-then-probe, pd-httpx path resolution, temp-file
buffering, backgrounding, rate limits). The shell `lib/*.sh` + `tools/*.sh` remain
as a readable reference.

## The discover pipeline

`subfinder` (passive) → `dnsx` (concurrent resolve, live only) → `httpx`
(projectdiscovery, minimal flags, temp-file output) → Shodan enrichment. Resolving
first avoids wasting the run on dead names; the binary resolves the projectdiscovery
`httpx` even when Python's `httpx` shadows it on PATH.

## The check engine

Native, parallel, rate-limited: security headers, TLS 1.0/1.1 acceptance,
unauthenticated exposure (**baseline-differential** — compared to a random path,
to defeat catch-all 200s), and component CVEs via OSV (filtered to unpatched).
`--deep` adds nuclei (batch), sslscan cipher enumeration, content discovery, and
screenshots. Findings persist **incrementally** so a time-bounded run never loses
partial results.

## Safety model

- **Authorization gate** in the core: `discover`/`test`/`sandbox` refuse without
  `--confirm` or an authorized `.secskills-scope.yml`. `--intrusive` needs a
  second confirmation. DoS and mass third-party scanning are always refused.
- **Scope confinement**: every probe checks the confirmed scope; out-of-scope
  hosts are skipped.
- **Untrusted target output**: every target-derived string is run through
  `neutralizeUntrusted` (strip invisible/bidi/control unicode, redact injection
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
internal/scope/       authorization: scope file, per-IP CIDR filter, signed
                      scope tokens, the gate notice
internal/netsec/      SSRF guard, shell quoting, host parsing
internal/fetch/       throttled free-source HTTP + non-destructive target client
internal/finding/     finding model, severity policy, detector registry,
                      capabilities, CVSS/OWASP/compliance mapping, evidence
                      ledger, findings store
internal/engine/      discover/test engine: checks, detector packs, adversarial
                      planner, edge mapping, deep scans, conformance + measure
internal/report/      Markdown/HTML/PDF/audit reports, lint, tickets,
                      SARIF/CycloneDX, run attestation
internal/exposure/    ASN/CIDR exposure pipeline (sweep → enrich → leak/db
                      checks → feeds → cvematch → lifecycle → delivery)
internal/probe/       embeddable probe layer: Observation store, guarded HTTP,
                      kprobe (no dependency on the rest)
internal/intel/       deterministic advisory × asset matcher, version ranges
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
lib/, tools/          shell reference + doctor.sh/ingest.sh + registry.tsv
examples/embed/       using internal/probe as a library
docs/                 this documentation
```

Dependencies point one way: `cmd/secskills` → `report` → `engine` →
`finding` → `kb`/`tooling`/`fetch`/`scope` → `netsec`/`textutil`/`jsonl`;
`exposure` sits beside `engine` on the same lower layers. `internal/probe` and
`internal/intel` import nothing else from the module.

## Tests

- `go test ./...` runs unit tests per package plus the **golden CLI suite**
  (`cmd/secskills/cli_golden_test.go`). The suite builds the real binary and runs
  it in a hermetic sandbox (temp HOME/TMPDIR/feed cache, whitelisted env,
  `PATH` with only `sh`, outbound HTTP sent to a dead proxy). It diffs
  normalized output against `cmd/secskills/testdata/golden/`: help and flags of
  every command, every authorization-gate refusal, the KB, MCP, conformance,
  measure, selftest, the exposure pipeline over `testdata/exposure/`, scope
  tokens, and the findings → report/tickets/SARIF/CycloneDX/attest path.
- It is black-box, so it holds across refactors. After an **intended** output
  change, regenerate and review the diff:
  `go test ./cmd/secskills -run TestGolden -update && git diff cmd/secskills/testdata/golden`.
- Coverage of the black-box suite:
  `SECSKILLS_GOLDEN_COVER=1 GOCOVERDIR=$(mktemp -d) go test ./cmd/secskills -run TestGolden`
  then `go tool covdata percent -i <dir>`.
- CI (`.github/workflows/ci.yml`): gofmt, vet, race tests, staticcheck,
  `go install`, cross-compile for linux/darwin/windows.
