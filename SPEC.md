# Specification: secskills

## Problem

Security work spans reading code, standing up a build to probe it, and testing a live system — and the canonical guidance for all three (OWASP Cheat Sheet Series, Top 10, ASVS, WSTG) is authoritative but scattered across a website tuned for human reading, not for an AI agent working a target. Practitioners lose time stitching methodology, tooling, and reference together by hand, and an AI assistant asked to "find what's exploitable here" has no packaged, on-disk security capability grounded in that guidance. secskills solves this for security-literate developers, explorers, pentesters, and red teamers: a Claude Code skill package that discovers a target's attack surface and conducts authorized OWASP-grounded testing across three input modes — source code, a standalone sandboxed artifact, and a live app/domain — producing a human-readable findings report. It subsumes the prior `redteam-pentest` skill's live surface-mapping and active-testing capabilities and grounds them in an on-disk OWASP knowledge base.

## Scope

**In scope**

- A Claude Code skill package `secskills`, installable via the plugin/marketplace mechanism.
- Three target input modes, each a complete path from target → discovery → tests → report:
  - **Source** — static review of code in a repo/path.
  - **Sandboxed artifact** — build/run the target in an isolated sandbox, then test the running instance.
  - **Live app/domain** (primary) — discover the reachable attack surface of a URL/domain and conduct authorized tests against it.
- Attack-surface discovery: DNS, subdomains, live services/ports, endpoints/routes, tech fingerprinting, exposed assets.
- Active testing mapped to OWASP Top 10 and cheat-sheet checks, per vulnerability class.
- An on-disk OWASP knowledge base (Cheat Sheet Series, Top 10, references to ASVS/WSTG) that grounds discovery, testing, and reporting.
- A mandatory authorization gate for any mode that touches a target the user does not own outright (live app/domain always; sandboxed artifact and source when they reach out).
- Findings report a human can read: severity, evidence, affected surface, remediation keyed to cheat sheets.
- Re-test / delta: re-probe prior findings and report what changed.
- Provenance + license compliance for redistributed OWASP content.
- Absorbs the capabilities previously in `redteam-pentest` (surface mapping, active OWASP assessment, report); that skill is superseded.

**Out of scope**

- Testing targets without authorization — enforced by the gate, never bypassed.
- Denial-of-service, load/stress attacks, or mass/untargeted scanning of third parties.
- Malware, C2 frameworks, persistence, or detection-evasion tooling for malicious use.
- Automated code remediation that rewrites the target's application code without user review.
- A hosted service, web UI, or database — the package is skills + on-disk content.
- Redistribution of non-OWASP or paid-license content.
- Telemetry or collection of user/target data beyond the local findings artifacts.

## Users

- **Pentester** — points secskills at an authorized live app/domain, gets surface map + OWASP-grounded test run + report.
- **Red teamer** — needs attack-path framing and per-class test recipes across an authorized engagement, within scope and rate limits.
- **Developer doing security work** — runs source mode on their repo, or sandbox mode on a build, to find exploitable issues before ship.
- **Explorer / security-curious dev** — learns a class from the knowledge base and sees it mapped to a real target's findings.
- **Appsec reviewer** — audits code or a running artifact against ASVS/Top 10 and produces findings.

## Functional Requirements

FR-1: The system SHALL package as a Claude Code skill bundle installable via the plugin/marketplace mechanism.

FR-2: The system SHALL accept a target in three modes: source (repo/path), sandboxed artifact (buildable/runnable target), live app/domain (URL/domain).

FR-3: For the live mode, the system SHALL discover the reachable attack surface: DNS/subdomains, live services and ports, HTTP endpoints/routes, technology fingerprint, and exposed assets.

FR-4: For the sandbox mode, the system SHALL build and/or run the target in an isolated sandbox and then discover and test the running instance.

FR-5: For the source mode, the system SHALL statically review code in scope and surface exploitable weaknesses keyed to cheat-sheet checks.

FR-6: The system SHALL conduct active tests mapped to the OWASP Top 10 and per-class cheat-sheet checks against the discovered surface (live and sandbox modes).

FR-7: The system SHALL present a mandatory authorization gate before any action that sends traffic to or executes against a target the user does not own, requiring explicit user confirmation of authorization and scope.
- FR-7.a: Live app/domain mode SHALL always require the gate.
- FR-7.b: Source mode with no outbound traffic SHALL NOT require the gate.

FR-8: The system SHALL enforce safety limits on active testing: request rate limiting and a bounded, in-scope target list (no traversal outside confirmed scope).

FR-9: The system SHALL produce a human-readable findings report: each finding has severity, affected surface, evidence, and remediation keyed to the relevant cheat sheet.

FR-10: The system SHALL support re-test/delta: given prior findings, re-probe each and report status changes (fixed/still-present/new).

FR-11: The system SHALL bundle an on-disk OWASP knowledge base derived from the Cheat Sheet Series and Top 10, grounding discovery, test selection, and remediation text.

FR-12: The system SHALL provide a router/index skill mapping a target and free-text intent to the relevant mode and test classes.

FR-13: The system SHALL cover, at first release, the OWASP Top 10 (Web) categories as testable classes with knowledge-base backing.

FR-14: For every redistributed OWASP source, the system SHALL record provenance (title, URL, upstream version/commit, license) and display CC BY-SA attribution.

FR-15: Knowledge-base content SHALL be plain markdown, readable by the agent without executing code, and usable offline at invoke time.

FR-16: The system SHALL provide a manifest listing every skill, its mode/class, and its source cheat sheet(s), and SHALL document that it supersedes `redteam-pentest`.

## Non-Functional Requirements

NFR-1: Safety: Active testing SHALL default to rate-limited, non-destructive probes; destructive or higher-impact tests SHALL be opt-in and separately confirmed.

NFR-2: Isolation: Sandbox mode SHALL run the target isolated from the host (no host filesystem/network access beyond what the test requires).

NFR-3: Offline knowledge: The knowledge base SHALL be usable with no network fetch at invoke time; only discovery/testing against a live target uses the network.

NFR-4: Scale: Knowledge base SHALL cover ≥ 30 OWASP cheat sheets and all Top 10 categories at first release, each skill loading only its own content.

NFR-5: Data retention: No telemetry. Findings and provenance are retained locally as report artifacts; no target data leaves the host except test traffic to the confirmed in-scope target.

NFR-6: Latency: Knowledge-base retrieval SHALL add < 1s overhead excluding model generation; live-test duration is target-dependent and reported.

NFR-7: Portability: Source and knowledge content SHALL be language/stack-agnostic; per-stack test recipes are additive.

## Interfaces

**Skills (CLI-invocable in Claude Code)** — names indicative, finalized in roadmap:
- `secskills` — router: target + intent → mode + relevant test classes.
- `secskills-discover` — attack-surface discovery for a live target.
- `secskills-test` — run OWASP-mapped active tests against discovered surface (live/sandbox); authorization-gated.
- `secskills-source` — static source review keyed to cheat sheets.
- `secskills-sandbox` — build/run target in isolation, then discover+test.
- `secskills-report` — assemble/refresh the findings report; supports re-test/delta.
- `secskills-kb` — OWASP knowledge base + Top 10 index lookup.

**External systems**
- Target under test (live domain/app, or built artifact) — network/exec at run time, in confirmed scope only.
- OWASP Cheat Sheet Series source repo — ingestion time only, not runtime.
- Discovery/test tooling available on host (DNS, HTTP, scanners) — invoked as available.

**Data formats at boundaries**
- Target spec: URL/domain, repo path, or build/run descriptor.
- Knowledge base: normalized markdown with provenance front-matter.
- Findings: structured records (severity, surface, evidence, remediation) + rendered markdown report.
- Manifest: machine-readable skill → mode/class → source list.

## Constraints

- Runtime: Claude Code skill package (SKILL.md format, plugin/marketplace bundle). No server, no database.
- OWASP content redistributed under CC BY-SA 4.0: attribution + share-alike + provenance preserved.
- Follow existing sec-skill conventions (SKILL.md + reference bundles + authorization gate), consistent with `ds-security-review` and the superseded `redteam-pentest`.
- Forbidden approaches:
  - No testing a target without passing the authorization gate.
  - No DoS, load/stress, or mass third-party scanning.
  - No malware/C2/persistence/evasion tooling for malicious use.
  - No runtime network fetch of knowledge-base content (offline-first).
  - No sandbox that shares host filesystem/network beyond test needs.
  - No telemetry.

## Acceptance Criteria

AC-1: Given the package installed, when the user lists skills, then `secskills` and its mode skills appear invocable.

AC-2: Given a live domain and authorization confirmed, when `secskills-discover` runs, then it returns a surface map (DNS/subdomains, live services, endpoints, tech fingerprint).

AC-3: Given a live target with no authorization confirmation, when a test/discovery action is requested, then the authorization gate blocks execution until the user confirms scope.

AC-4: Given a buildable target and sandbox mode, when `secskills-sandbox` runs, then the target runs isolated from the host and is tested as a running instance.

AC-5: Given a repo path and source mode, when `secskills-source` runs, then it returns findings keyed to specific cheat-sheet checks and shows no authorization gate.

AC-6: Given a discovered surface, when `secskills-test` runs, then it executes OWASP Top 10-mapped tests and records per-finding evidence.

AC-7: Given active testing, when it runs, then requests are rate-limited and confined to the confirmed in-scope target list.

AC-8: Given completed testing, when the report is produced, then each finding shows severity, affected surface, evidence, and cheat-sheet-keyed remediation.

AC-9: Given prior findings, when re-test runs, then each is reported as fixed / still-present / new.

AC-10: Given no network, when `secskills-kb` is invoked, then it returns cheat-sheet/Top 10 content without a network call.

AC-11: Given any knowledge-base file, when opened, then a provenance block names source title/URL/version and CC BY-SA license; package root carries the license text.

AC-12: Given first release, when the manifest is read, then ≥ 30 cheat sheets, all Top 10 categories, and a note superseding `redteam-pentest` are present.

AC-13: Given a free-text intent + target, when `secskills` router runs, then it selects the correct mode and relevant test classes.

**Coverage**

- FR-1 → AC-1
- FR-2 → AC-2, AC-4, AC-5
- FR-3 → AC-2
- FR-4 → AC-4
- FR-5 → AC-5
- FR-6 → AC-6
- FR-7 / FR-7.a → AC-3
- FR-7.b → AC-5
- FR-8 → AC-7
- FR-9 → AC-8
- FR-10 → AC-9
- FR-11 → AC-10
- FR-12 → AC-13
- FR-13 → AC-6, AC-12
- FR-14 → AC-11
- FR-15 → AC-10
- FR-16 → AC-12

## Decisions (resolved)

D-1 (tooling): Graceful degradation. Baseline `curl`, `dig`, `jq`, `python3` assumed present. Power tools (subfinder, amass, httpx, nuclei, katana, dalfox, trufflehog, osv-scanner, ast-grep, sslscan, docker) used when found via `command -v`, skipped with a recorded note when absent. No hard-stop on a missing optional tool.

D-2 (sandbox): Docker. Ephemeral container, no host filesystem mounts, dropped capabilities, egress restricted to the target under test. If docker is absent, sandbox mode refuses cleanly — never a degraded pseudo-isolation.

D-3 (redteam migration): Restructure the shell under the 3-mode model; reuse internals verbatim — phases become the bodies of `secskills-discover`/`secskills-test`; report template, finding template, glossary, `check_prompt_injection`, and `emit_finding` are lifted unchanged.

D-4 (findings store): Reuse the run-file JSON schema and retest diff loop verbatim; relocate the store to `~/.secskills-findings/<target>/`.

D-5 (authz gate): Per-invocation confirmation is the default for any target-touching action. An optional `.secskills-scope.yml` (target list + expiry timestamp) is honored within a single session to avoid re-confirming each step; expired or absent → per-invocation confirm.

D-6 (destructive policy): Non-destructive by default — GET/HEAD/OPTIONS, read-only API reads, rate-limited, bounded lockout probe (≤5 attempts). Intrusive tests (write/PUT probes, credential stuffing, workflow-abuse) are gated behind an `--intrusive` flag plus a second explicit confirmation.

D-7 (KB granularity): Per-class grouping (~15–20 skills), aligned to OWASP Top 10 + ability domains; each skill bundles several related cheat sheets. Chosen for NFR-2 (each skill loads only its own content).

D-8 (ingestion): Vendored snapshot committed in-repo plus a re-runnable refresh script. Offline-first (NFR-3); refresh reports changed files (FR-10).

D-9 (architecture / multi-agent): Ship a single stdlib-only Go binary `secskills` as the portable core — all logic, no LLM dependency — with the OWASP KB and ast-grep rules embedded via `go:embed` (offline). External pentest tools are shelled out, never reimplemented. Thin per-agent adapters share the binary: Claude Code (SKILL.md + plugin, or `secskills mcp`), opencode (`AGENTS.md` + `.opencode/command`, or `opencode.json` MCP), and any MCP client via a hand-rolled JSON-RPC 2.0 stdio server. The authorization gate lives in the core (`--confirm`); live modes are not auto-exposed over MCP. Shell `lib/*.sh` remain as reference/fallback.
