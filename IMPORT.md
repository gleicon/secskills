# Import map — vendored assets → secskills

Reusable prior work copied into `vendor/`, verbatim, read-only. Source skills were **not** modified; these are copies to build from. This is the author's own prior work (not OWASP content) — no external license attaches; treat as internal source.

## What was imported

| Asset | Source (read-only) | Size |
|-------|--------------------|------|
| `vendor/redteam-pentest.md` | `~/.claude/commands/redteam-pentest.md` | 1896 lines |
| `vendor/xss-assist.md` | `~/.claude/commands/xss-assist.md` | 490 lines |
| `vendor/ast-grep-rules/` | `~/.claude/commands/rules/` | 118 rules + `sgconfig.yml` |

## `redteam-pentest.md` — the live-mode engine

This is effectively the whole **live app/domain** mode already built. Its phases map directly onto the roadmap:

| Source phase | secskills mode / skill | Roadmap task |
|--------------|------------------------|--------------|
| Authorization Gate | authz gate primitive | Authorization gate + safety limits |
| Prompt Injection Defense (`check_prompt_injection`) | safety limits | Authorization gate + safety limits |
| Tool Verification (subfinder/amass/httpx/nuclei/…) | tooling baseline | (Open Q1 — minimum-tooling) |
| Phase 1 Passive Recon (subdomains, CT logs, DNS, ASN) | `secskills-discover` | Live mode — discover slice |
| Phase 2 Active Enum (httpx, headers, nuclei, server CVE) | `secskills-discover` + `secskills-test` | Live discover / test |
| Phase 3 Container Registry | `secskills-test` (exposure class) | Live test + report |
| Phase 4 Identity Provider (Keycloak/OIDC) | `secskills-test` | Live test + report |
| Phase 5 Monitoring/Telemetry exposure | `secskills-test` | Live test + report |
| Phase 5b Cloud Object Storage | `secskills-test` | Live test + report |
| Phase 6 OWASP Top 10 (A01–A10) | `secskills-test` + KB | Live test + report / KB coverage |
| Phase 7 OSV CVE analysis | `secskills-test` (A06) | Live test + report |
| Phase 9 Authenticated session testing | `secskills-test` (auth surface) | Live test + report |
| Report Generation + Finding Format + Glossary | `secskills-report` | Live test + report |
| Phase 8 Findings Store + Retest (`~/.rtp-findings/`) | `secskills-report` re-test/delta | Re-test / delta |

Reusable primitives to lift out: `check_prompt_injection`, `emit_finding`, the run-file JSON schema, the retest diff loop, the report template, the finding template, the glossary.

Open decisions this forces (already in SPEC Open Questions):
- Q3 — reuse these phases verbatim or restructure under the 3-mode model.
- Q4 — reuse `~/.rtp-findings/` store layout or a new one.
- Q1 — the Tool Verification table is the de-facto minimum-tooling baseline.

## `ast-grep-rules/` — the source-mode engine

118 structural rules, two families, six languages (Go, JS, TS, Python, PHP, Ruby):
- `sinks/` — real vulnerability sinks: injection (eval/exec/system/SSTI/SQL), XSS (innerHTML/dangerouslySetInnerHTML/document.write), hardcoded secrets, LFI, deserialization (pickle/Marshal/yaml).
- `vibe/` — AI/vibe-code anti-patterns: commented-out auth, disabled CSRF, CORS wildcard, `Math.random` for crypto, `NODE_ENV`/`DEBUG` security bypass, TLS `InsecureSkipVerify`, prototype pollution, TOCTOU.

Maps to **source mode** (`secskills-source`) — Roadmap task "Source mode slice". `sgconfig.yml` drives `ast-grep scan --config`. These are the finding engine; the OWASP KB supplies the remediation text keyed to each hit.

## `xss-assist.md` — injection test-class deep-dive

Interactive XSS payload crafting: context interrogation, CSP bypass, WAF bypass, blind XSS callback. Maps to a **test class** inside `secskills-test` (A03 Injection / XSS), invoked when discover/test surfaces an XSS candidate. redteam-pentest already has "→ XSS-ASSIST trigger" hooks — preserve as an internal handoff, not an external skill call.

## Not imported / still needed

- OWASP Cheat Sheet Series content (the KB itself) — separate ingestion, CC BY-SA, per roadmap "Ingestion" + "KB coverage batch".
- Sandbox mechanism — no prior art in these assets; net-new (SPEC Open Q2).
- Package/manifest scaffolding — net-new.
