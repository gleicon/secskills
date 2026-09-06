# secskills

**Your security team, as a single binary.** secskills scopes an engagement,
discovers a target's attack surface, runs authorized OWASP-mapped testing, and
produces a professional pentest report — from a source repo, a sandboxed
artifact, or a live app/domain.

Grounded in an on-disk OWASP knowledge base (Web Top 10 2021, Mobile Top 10 2024,
LLM/Agentic Top 10 2025, plus the Cheat Sheet Series). Portable across **Claude
Code**, **opencode**, and any **MCP** client. Supersedes `redteam-pentest`.

```bash
make install                          # build + install the `secskills` binary
secskills doctor                      # preflight: which of ~63 tools are present
secskills profile example.com         # passive OSINT brief (no target traffic)
secskills discover example.com --confirm
secskills test example.com --confirm --deep
secskills report --pdf example.com --output report.pdf
```

---

## Why

Security work spans reading code, standing up a build to probe it, and testing a
live system — and the canonical guidance for all three (OWASP Top 10, Cheat Sheet
Series, ASVS, WSTG) is scattered across a website built for humans, not for an
agent working a target. secskills packages the methodology, the tooling, and the
reference into one binary an agent (or a person) drives, with an authorization
gate and rate limiting built into the core.

## Three modes

| Mode | Target | Command | Gate |
|------|--------|---------|------|
| **source** | repo / path | `secskills source <path>` | none (no traffic) |
| **sandbox** | buildable artifact | `secskills sandbox <ctx> --confirm` | authz + Docker isolation |
| **live** | URL / domain | `secskills discover` → `secskills test` | authz gate |

## Workflow

1. **Intake** (`/secskills-intake`) — a guided interview that researches the
   target (passive OSINT), grills you on authorization, scope, target class,
   credentials, and rules of engagement, then writes a locked
   `.secskills-scope.yml` + `ENGAGEMENT.md`. Nothing loose before testing.
2. **Discover** — `subfinder → dnsx → httpx`, Shodan enrichment, scope-confined.
3. **Test** — security headers, TLS posture, unauthenticated exposure
   (baseline-differential), OSV component CVEs; `--deep` adds nuclei, sslscan
   cipher enumeration, content discovery, and screenshots. Credential-gated
   authenticated pass; otherwise marked *not available*.
4. **Report** — Markdown, HTML, or a **professional PDF** (big-4 style) with
   SOC 2 / ISO 27001 / PCI-DSS control mapping and per-finding owning team.

## Features

- **Authorization gate** in the core — live/sandbox refuse without `--confirm` or
  an authorized scope file. Non-destructive by default; intrusive needs a second
  confirmation. No DoS, no unauthorized targets.
- **~63 tools, graceful degradation** — `secskills doctor` verifies each (per
  mode/category), prints the install command, and detects build collisions
  (e.g. Python `httpx` shadowing projectdiscovery). Absent tools are skipped,
  never fatal.
- **OWASP-grounded findings** — every finding carries an OWASP category (Web /
  Mobile / LLM), CWE, OSV CVEs, an owning team, and SOC 2 / ISO / PCI controls;
  remediation text is pulled from the embedded OWASP cheat sheets, not a template.
- **Offline knowledge base** — 40+ cheat sheets embedded via `go:embed`;
  `secskills kb <class>` and `secskills recipes <class>` (Node/Python/Go).
- **Findings store + re-test** — persistent runs; `report --retest` re-verifies
  each finding with a structured Go probe (no shell) → fixed / still-present / regressed.
- **Token hygiene** — `secskills compress|scrub|scan` (tldt) shrink OSINT, redact
  PII/secrets, and flag prompt injection in untrusted target output.

## Multi-agent

One binary, thin adapters (see `ADAPTERS.md`):

- **Claude Code** — `skills/*/SKILL.md` + `.claude-plugin/`, or `claude mcp add secskills -- secskills mcp`.
- **opencode** — `AGENTS.md` + `.opencode/command/secskills.md`, or `opencode.json` MCP.
- **Any MCP client** — `secskills mcp` (JSON-RPC 2.0 stdio; tools: doctor, kb, recipes, source_scan, fetch).

## Install

```bash
make install    # go build → $GOPATH/bin/secskills
secskills doctor        # see what tools you have; --category report checks the PDF browser
```

Requires Go 1.26+. Runtime tools are optional (graceful degradation) — see
[`INSTALL.md`](INSTALL.md). Headless Chrome/Chromium is needed only for PDF and
screenshots.

## Documentation

- [Getting started](docs/getting-started.md)
- [Usage & commands](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Reporting & compliance](docs/reporting.md)
- Full command list: `secskills help`

## Safety

- Authorization gate before any target-touching action.
- Non-destructive, rate-limited, scope-confined by default.
- Target output is untrusted data — scanned for prompt injection, never followed.
- The findings store (`~/.secskills-findings/`) is sensitive — treat like a
  credentials store; never commit engagement data.

## License

- Code (`skills/`, `lib/`, `tools/`, `*.go`, `rules/`): **MIT** — see [`LICENSE`](LICENSE).
- Knowledge base (`kb/`): OWASP Cheat Sheet Series / Top 10, **CC BY-SA 4.0** —
  see [`LICENSE-OWASP.md`](LICENSE-OWASP.md).

## Legal

secskills tests systems. Only run it against targets you are **authorized** to
test. The authorization gate is a control, not legal cover — you are responsible
for having written permission.
