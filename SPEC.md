# Specification: secskills

How the secskills engine works as built. Requirement and decision IDs are kept
because the code cites them. Network mode (ASN/CIDR blocks) is specified in
[`SPEC-NETWORK.md`](SPEC-NETWORK.md).

## Problem

Security work spans reading code, standing up a build to probe it, and testing a
live system. The canonical guidance for all three (OWASP Cheat Sheet Series, Top
10, ASVS, WSTG) is written for people reading a website, not for an agent
working a target. secskills packages the methodology, the tooling, and the
reference into one binary that a person or an agent drives, with an
authorization gate and rate limiting in the core.

## Scope

In scope:

- One binary with three target modes, each a full path from target to report:
  - **Source**: static review of code in a repo or path.
  - **Sandbox**: build and run an artifact in an isolated container, then test it.
  - **Live**: discover a domain's reachable attack surface and test it.
- Network blocks (ASN/CIDR) through the same findings and reports (`SPEC-NETWORK.md`).
- Active, non-destructive tests mapped to the OWASP Top 10 and cheat-sheet checks.
- An embedded OWASP knowledge base and per-stack recipes, usable offline.
- An authorization gate before anything that touches a target.
- Reports (Markdown, HTML, PDF, auditor), retests, tickets, SARIF and CycloneDX.
- Provenance and license compliance for redistributed OWASP content.

Out of scope:

- Testing without authorization: enforced by the gate, never bypassed.
- Denial of service, load testing, or untargeted scanning of third parties.
- Malware, C2, persistence, or detection-evasion tooling.
- Rewriting the target's code without review.
- A hosted service, web UI, or database.
- Telemetry, or sending target data anywhere except test traffic to the target.

## Users

- **Pentester**: points secskills at an authorized domain, gets a surface map, a test run, and a report.
- **Red teamer**: needs attack-path framing and per-class tests within scope and rate limits.
- **Developer**: runs source mode on a repo, or sandbox mode on a build, before shipping.
- **Network owner**: sweeps an ASN or CIDR for exposures and CVE leads.
- **Appsec reviewer**: audits code or a running artifact and produces findings.

## Functional requirements

- **FR-1** Install as a single static binary (`go install`, or a checksummed
  release binary), and as a Claude Code plugin whose skills drive the binary.
- **FR-2** Accept a target in each mode: a path (source), a build context
  (sandbox), a URL or domain (live), a CIDR or ASN (network).
- **FR-3** Live mode discovers DNS and subdomains, live services, HTTP endpoints,
  technology fingerprints, and exposed assets.
- **FR-4** Sandbox mode builds the target, runs it isolated, and tests the
  running instance.
- **FR-5** Source mode reviews code with the embedded ast-grep rules and keys
  each finding to a knowledge-base class.
- **FR-6** Live and sandbox modes run OWASP Top 10-mapped checks against the
  discovered surface.
- **FR-7** An authorization gate precedes any action that sends traffic to, or
  executes against, a target: `--confirm`, or an authorized, unexpired scope file.
  - **FR-7.a** Live and network modes always pass the gate.
  - **FR-7.b** Source mode sends no traffic and needs no gate.
- **FR-8** Active testing is rate-limited and confined to the confirmed scope.
- **FR-9** Reports give each finding a severity, affected asset, evidence,
  validation state, and remediation keyed to a cheat sheet.
- **FR-10** Retest re-probes each stored finding with a structured check and
  reports fixed, still present, regressed, or inconclusive.
- **FR-11** The OWASP knowledge base is embedded and grounds test selection and
  remediation text.
- **FR-12** A router skill maps a target and free-text intent to a mode and test classes.
- **FR-13** All OWASP Top 10 (Web) categories are testable classes with
  knowledge-base backing.
- **FR-14** Every redistributed OWASP source records provenance (title, URL,
  upstream version, license) and CC BY-SA attribution.
- **FR-15** Knowledge-base content is plain Markdown, readable offline.
- **FR-16** `.claude-plugin/plugin.json` lists the package for Claude Code and
  `secskills help` lists every command.

## Non-functional requirements

- **NFR-1 Safety.** Tests default to rate-limited, non-destructive probes.
  Destructive or credential tests are opt-in and separately confirmed.
- **NFR-2 Isolation.** Sandbox mode runs the target with no host mounts, all
  capabilities dropped, no new privileges, and its port published to loopback only.
- **NFR-3 Offline knowledge.** The knowledge base needs no network at invoke time.
- **NFR-4 Coverage.** At least 30 OWASP cheat sheets and all Top 10 categories.
- **NFR-5 Data.** No telemetry. Findings and evidence stay local, owner-only.
- **NFR-6 Portability.** Linux, macOS, and Windows builds; no CGO.

## Interfaces

- **CLI**: `secskills <command>`; see `secskills help` and `docs/usage.md`.
- **Skills** (Claude Code): `secskills` (router), `secskills-intake`,
  `secskills-discover`, `secskills-test`, `secskills-source`, `secskills-sandbox`,
  `secskills-report`, `secskills-kb`, `secskills-doctor`. Each calls the binary.
- **MCP**: `secskills mcp`, read-only tools only. No MCP tool can start a scan.
- **External tools**: run when present, skipped with a note when absent (D-1).
- **Data**: findings as JSON in the workdir and in `~/.secskills-findings/<target>/`
  runs; evidence objects content-addressed in an append-only manifest; network
  observations as JSONL.

## Acceptance criteria

- **AC-1** The plugin's skills are listed and invocable once installed.
- **AC-2** With authorization, `discover` returns a surface map.
- **AC-3** Without authorization, every target-touching command refuses. (golden test)
- **AC-4** `sandbox` runs the target isolated and tests it; without Docker it refuses.
- **AC-5** `source` returns findings keyed to cheat-sheet classes and never shows the gate.
- **AC-6** `test` runs Top 10-mapped checks and records evidence per finding.
- **AC-7** Requests are rate-limited and confined to the confirmed scope.
- **AC-8** Reports show severity, asset, evidence, and keyed remediation for each finding.
- **AC-9** Retest reports each finding as fixed, still present, regressed, or inconclusive.
- **AC-10** `kb` returns content with no network call.
- **AC-11** Every knowledge-base file carries a provenance block; the package carries the license text.
- **AC-13** The router skill selects the right mode and classes for an intent.

## Decisions

- **D-1 Tooling.** Graceful degradation. The binary needs no external tool
  except Docker for sandbox mode. Power tools (subfinder, httpx, nuclei, katana,
  dalfox, sslscan, osv-scanner, ast-grep, …) are used when present and skipped
  with a recorded note when absent.
- **D-2 Sandbox.** Docker, ephemeral, no host mounts, capabilities dropped. If
  Docker is absent, sandbox mode refuses; it never fakes isolation.
- **D-3 Playbooks.** The earlier `redteam-pentest` and `xss-assist` playbooks are
  kept in `thirdparty/` as manual methodology the skills point to; their
  automatable checks are implemented natively in the binary.
- **D-4 Findings store.** Each saved run is a JSON file under
  `~/.secskills-findings/<target>/` with a `latest` link; retest writes a new run.
- **D-5 Authorization.** `--confirm` per invocation, or a `.secskills-scope.yml`
  that is authorized, unexpired, owned by the operator, and not group- or
  world-writable.
- **D-6 Destructive policy.** Default tests only read. Write and credential tests
  need `--intrusive` and `--intrusive-confirm`.
- **D-7 Knowledge-base granularity.** One directory per class (12 classes), each
  bundling related cheat sheets, so a skill loads only its class.
- **D-8 Ingestion.** A vendored snapshot committed in the repo, refreshed by
  `tools/ingest.sh`, which reports the files that changed.
- **D-9 Architecture.** One Go binary holds all logic, with the knowledge base and
  rules embedded. External tools are run, never reimplemented. Agent adapters
  (skills, opencode command, MCP) are thin and share the binary. The gate lives
  in the core; live modes are not exposed over MCP.
