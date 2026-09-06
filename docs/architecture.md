# Architecture

## One binary, thin adapters

secskills is a single stdlib-only Go binary. All logic lives there — no LLM
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
- **Untrusted target output**: scanned for prompt injection (`check_prompt_injection`
  + tldt), treated as data, never followed.

## Classification

Every finding is mapped to an OWASP category (Web Top 10 2021 / Mobile Top 10 2024
/ LLM Top 10 2025), a CWE, an OWASP Cheat Sheet class, OSV CVEs, an owning team,
and SOC 2 / ISO 27001 / PCI-DSS controls — so the report is both actionable and
audit-usable.

## Source layout

```
*.go              command implementations (doctor, profile, scope, mode, checks,
                  deep, enrich, compliance, report_*, mcp, shodan, tooling, …)
kb/               OWASP knowledge base (embedded, CC BY-SA)
recipes/          per-stack secure/vulnerable snippets (embedded)
rules/            ast-grep rules (source-mode engine, embedded via vendor/)
skills/           Claude Code SKILL.md adapters
lib/, tools/      shell reference + doctor.sh/ingest.sh + registry.tsv
docs/             this documentation
```
