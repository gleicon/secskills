# Roadmap: secskills

Status: **v0.1.0 built** (2026-09-05). Decisions D-1..D-8 in `SPEC.md`.
All power tools present on host; source-mode ast-grep engine verified live.

## Enabling foundation

- [x] **Authorization gate + safety limits.** `lib/authz-gate.md` (gate + scope file + intrusive policy) and `lib/safety.sh` (`secskills_scope_check`, `secskills_rate_limit`, `check_prompt_injection`). (FR-7, FR-8, NFR-1 · AC-3, AC-7)
- [x] **KB skeleton + license.** `kb/` with provenance blocks; `LICENSE-OWASP.md` (CC BY-SA 4.0) at root. (FR-11, FR-14, FR-15 · AC-10, AC-11)
- [x] **Ingestion, re-runnable.** `tools/ingest.sh` — fetch upstream, drift report, snapshot rev, `--check`. (FR-11 · AC-11)

## Mode slices

- [x] **Live mode — discover.** `secskills-discover` (wraps vendor Phases 1-2), gated, scope-confined. (FR-2, FR-3, FR-7.a · AC-2, AC-3)
- [x] **Live mode — test + report.** `secskills-test` (vendor Phases 3-9, Top 10 → KB) + `secskills-report` (template + findings store). (FR-6, FR-9, FR-13 · AC-6, AC-7, AC-8)
- [x] **Source mode.** `secskills-source` on 117 ast-grep rules; no gate; KB-keyed remediation. Verified: catches hardcoded secret + command injection. (FR-5, FR-7.b · AC-5)
- [x] **Sandbox mode.** `secskills-sandbox`: Docker isolation (no mounts, cap-drop, egress-restricted), refuses if Docker absent. (FR-4, NFR-2 · AC-4)

## Cross-cutting

- [x] **Router.** `secskills`: target + intent → mode + OWASP classes. (FR-12 · AC-13)
- [x] **Re-test / delta.** `lib/findings-store.sh:secskills_retest` — open/mitigated/regressed + hash drift. (FR-10 · AC-9)
- [x] **KB coverage.** 40 cheat sheets, 9 classes + Top 10 index, all A01-A10. (FR-13, NFR-4 · AC-6, AC-12)
- [x] **Manifest + supersede note.** `manifest.json` (skills, classes, coverage, `supersedes: redteam-pentest`). (FR-16 · AC-12)
- [x] **Doctor / preflight.** `tools/doctor.sh` + `secskills-doctor` skill: per-mode tool check (baseline vs power), brew/apt/go/cargo install commands for macOS + Ubuntu, `--mode`/`--json`/`--quiet`, exit 1 on missing baseline. `INSTALL.md` documents the full matrix. Verified across modes. (D-1)
- [x] **Package + install.** `.claude-plugin/plugin.json`; 8 SKILL.md discoverable; scripts executable, `bash -n` clean. (FR-1 · AC-1)

## v0.2 — arsenal + token hygiene (2026-09-05)

- [x] **Expanded tool arsenal.** `tools/doctor.sh` registry grown to ~60 tools / 17 categories (osint, dns, http, port, vuln, cve, secrets, content, params, tls, cloud, exploit, oob, source, optimizer). `--category`, `--tools`, `--list-categories` filters. Generic installer (go/cargo/pipx/npm/cask/script/apt). Added shodan, fofax; validated PD stack. `INSTALL.md` updated.
- [x] **tldt token optimizer.** `lib/tldt.sh`: `secskills_compress` / `secskills_digest_list` (shrink OSINT before analysis), `secskills_scrub_pii` (redact emails/keys/tokens for reports — replaces manual email-strip), `secskills_scan_untrusted` (tldt injection+PII detection layered over `check_prompt_injection`). Timeout-guarded, degrades to cat/grep. Wired into discover/test/report skills. Verified against the real binary.
- [x] **OSINT sources + API keys.** `lib/osint-sources.md`: keyless (crt.sh/Wayback/CommonCrawl/OTX via gau) vs keyed (shodan/fofa/github/chaos/censys/VT). Credential resolution env→config→skip-with-note; keys never echoed. Shodan CLI/token/systemwide documented.

## v0.3 — Go binary + multi-agent (2026-09-05)

- [x] **Single Go binary (`secskills`), stdlib-only.** Subcommands: doctor, source, discover, test, sandbox, kb, fetch/post, compress/scrub/scan, report, mcp. `go:embed` bundles the OWASP KB + 117 ast-grep rules + tool registry — runs offline. External tools shelled out, never reimplemented. `go vet` + `go test` pass (registry, renderInstall, modeMatch, source-interval, KB embed).
- [x] **Throttle/fetch in Go.** Per-source intervals + exponential backoff honoring Retry-After; verified live (OSV 32 CVEs, crt.sh discover path).
- [x] **MCP stdio server.** Hand-rolled JSON-RPC 2.0 (zero deps), protocol 2024-11-05; tools: doctor, kb_list, kb_get, source_scan, fetch. Live discover/test intentionally not auto-exposed (gate). Handshake verified.
- [x] **Multi-agent adapters.** Claude Code (skills + `claude mcp add`), opencode (`AGENTS.md` + `.opencode/command/secskills.md` + `opencode.json` MCP), generic MCP. `ADAPTERS.md` documents registration; `Makefile` (build/test/install/mcp-check).
- [x] **Authorization gate in the core.** `discover`/`test`/`sandbox` refuse without `--confirm`; `--intrusive` needs a second confirm. Sandbox refuses without Docker.

## v0.4 — gaps closed, nothing deferred (2026-09-05)

- [x] **Full `discover` pipeline.** Concurrent subdomain enum (subfinder or throttled crt.sh) → concurrent DNS resolve → rate-limited live-host probe → artifacts (`subs.txt`, `resolved.txt`, `live_hosts.json`) in workdir; tech flagging; scope-confined.
- [x] **Full `test` pipeline.** Native check engine (`checks.go`): security headers, TLS 1.0/1.1 acceptance, exposure paths (/metrics, /actuator, /.git, pprof), nuclei parse. Emits findings to the store; rate-limited, scope-checked, `--intrusive` needs `--intrusive-confirm`.
- [x] **Real `sandbox`.** Docker build → isolated run (`--cap-drop=ALL`, `--security-opt=no-new-privileges`, no mounts, published to 127.0.0.1) → probe instance → guaranteed teardown. Refuses without Docker.
- [x] **Native findings store.** `findings add|write-run|list|show`; `report --render` (full markdown) + `--retest`. No longer needs shell/model to persist.
- [x] **End-to-end `selftest`.** Spins a local disposable weak server, runs the check engine → store → run-file → render, asserts findings. Wired into `go test` (`TestSelftest`) and `make selftest`. Authorized by construction; no third party.
- [x] **Registry single-source.** `tools/doctor.sh` now reads `tools/registry.tsv` (Go embeds the same file). Shell↔Go parity verified (62==62, identical tool set).
- [x] **Real KB vendoring.** `tools/ingest.sh --vendor` copies each upstream cheat sheet into `kb/<class>/vendored/` with a provenance header (CC BY-SA). Offline after. Drift report + snapshot rev retained.
- [x] **Per-stack recipes.** `recipes/` — Node/Python/Go secure-vs-vulnerable for injection, access-control, auth-session, crypto-secrets, config-exposure, ssrf-xxe. Embedded; served via `secskills recipes <class>` and MCP `recipes_get`. Remaining classes map to KB (recipes/README.md).

All prior follow-ups resolved. Nothing deferred.

## Backlog (net-new ideas, not gaps)

- Live engagement against a real authorized external target (needs the operator's scope + written authorization — cannot be self-tested).
- Additional nuclei/OSV enrichment passes and screenshot capture in `discover`.

- KB entries are curated summaries with upstream provenance; `ingest.sh` reports drift but full HTML→md re-vendoring of each sheet is manual. Wire pandoc normalization if verbatim upstream text is wanted.
- Per-stack test recipes (SPEC Open item, deferred): KB is stack-agnostic; add Node/Python/Go examples additively later.
- End-to-end live run against an authorized target to exercise discover→test→report on real output.
