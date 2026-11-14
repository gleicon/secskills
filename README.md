# secskills

[![ci](https://github.com/gleicon/secskills/actions/workflows/ci.yml/badge.svg)](https://github.com/gleicon/secskills/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/gleicon/secskills)](https://github.com/gleicon/secskills/releases/latest)

**Website: <https://gleicon.github.io/secskills/>** (install, usage, common cases, safety model)

**Your security team, as a single binary.** secskills scopes an engagement,
discovers a target's attack surface, runs authorized OWASP-mapped testing, and
produces a professional pentest report — from a source repo, a sandboxed
artifact, or a live app/domain.

Grounded in an on-disk OWASP knowledge base (Web Top 10 2021, Mobile Top 10 2024,
LLM/Agentic Top 10 2025, plus the Cheat Sheet Series). Portable across **Claude
Code**, **opencode**, and any **MCP** client. Supersedes `redteam-pentest`.

```bash
go install github.com/gleicon/secskills/cmd/secskills@latest
secskills doctor                      # which of the 60+ optional tools are present
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
| **exposure** | ASN / CIDR you own | `secskills discover --cidr` → `enrich` → `cvematch` | authz gate, per IP |

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
- **60+ tools, graceful degradation** — `secskills doctor` verifies each (per
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

## Assurance & audit-grade evidence

secskills is an **assessment-record system**, not just a report generator. The raw
observation is the system of record; the report is a view over it.

- **Immutable evidence objects** — content-addressed `EV-*` artifacts (HTTP/TLS/
  DNS/cert transcripts), append-only manifest, referenced per finding.
- **Run attestation + signing** — each run records SHA-256 over findings, scope
  manifest, ruleset, evidence bundle and config, plus build commit and source IP;
  signed with ed25519 (`secskills attest --sign/--verify`).
- **Control Test Ledger** — negative evidence (tested/passed/failed/inconclusive/
  N-A per control family); an unreachable probe is INCONCLUSIVE, never a silent pass.
- **Stable finding keys** — derived from semantics (detector + normalized asset +
  control), invariant under scheme/slash/port/order; the retest disposition
  (FIXED/OPEN/REGRESSED/INCONCLUSIVE) is keyed by it.
- **Detector quality scorecard** — measured precision/recall from an offline
  regression corpus (`secskills conformance`), enforced as a build gate.
- **Formal evidence state machine**, **severity rubric independent of CVSS**, and
  **auditable human adjudication** (`secskills override` — reviewed vs automated,
  never a silent mutation).
- **Root-cause clustering** — collapses N endpoint observations into shared-config
  groups (ingress/cert/ASN) with the grouping reason stated.
- **Non-destructive depth packs** — tech fingerprinting (Argo CD/Harbor/Vault/
  Grafana/Keycloak/MinIO/...), OIDC/OpenAPI/GraphQL surface, dangling-CNAME
  takeover *candidates*, public object-storage — plus differential CORS/exposure
  testing and environmental-ambiguity handling.
- **Three deliverables** — full technical report, concise `report --audit` for
  external auditors, and a machine-readable `attestation.json`.

### Adversarial engine

- **Runtime capability planner** — discoveries trigger follow-up probes at runtime
  (a disclosed internal hostname is resolved externally; a fingerprinted version
  runs an OSV CVE-applicability probe). Every decision is a persisted attack-graph
  edge (`planner-graph.jsonl`) with an explicit termination reason.
- **Technology fingerprint registry** — data-driven (`fingerprints.json` + overlay),
  grows like Wappalyzer/Shodan: `secskills fp list|add|import` (ingests Wappalyzer
  `technologies.json` or favicon mmh3 hashes). Fingerprints trigger second-stage
  packs (object store, Elasticsearch, Grafana, Vault, Consul, Argo CD, Harbor,
  Kubernetes, GitLab, Jenkins, …).
- **Per-technology mini-workflows** — a fingerprinted service triggers an ordered
  pivot tree (object store, Harbor, Kong, Grafana, Elasticsearch, Vault), each
  step a depth-stamped planner edge that stops at the proof boundary.
- **Edge & defense recon** — CDN/WAF fingerprint, favicon/cert Shodan+Censys
  looking-glass for origin IPs, direct-origin bypass (leaf-cert correlated),
  trusted-header ACL bypass.
- **Engine self-measurement** — `secskills measure` runs the live detectors against
  a local vulnerable+safe corpus and reports precision/recall (caught a real bug).
- **Continuous mode** — `secskills watch --interval` re-assesses and reports posture
  drift (NEW/FIXED/REGRESSED by finding key).
- **Interop + integrity** — `secskills export --format sarif|cyclonedx` (SARIF 2.1.0,
  CycloneDX 1.5 + VEX); signed tamper-evident evidence chain (`attest --verify`);
  self-hostable `secskills oast-server` for blind-SSRF validation;
  `secskills integrity snapshot|verify --confirm` for sha256 response baselines
  (AC-1 indicator for a rewriting LLM intermediary).
- **Credentialed depth** — JWT inspection, session-cookie flags, BOLA/IDOR
  differential (`--auth-token-b`).

## Exposure mode (network blocks)

For an ASN or CIDR you are authorized to assess: a cheap, rate-limited sweep
stores service observations, then offline joins turn them into ranked findings.

```bash
secskills discover --cidr 203.0.113.0/24 --confirm     # per-IP gate; > /20 needs --allow-large
secskills enrich    --workdir <wd> --confirm          # product / version / CPE
secskills leakcheck --workdir <wd> --confirm          # exposed .git/.env, open datastores
secskills feed kev && secskills feed epss && secskills feed nvd --product openssh
secskills cvematch  --workdir <wd>                    # KEV first, then EPSS-ranked
secskills lifecycle reconcile --workdir <wd>          # fixed / regressed / triaged
secskills prefix-report --workdir <wd>                # Markdown report for the block owner
```

Capture on a VM and analyze offline with `make bundle` and `deploy/`
([docs/offline-vm.md](docs/offline-vm.md)). Recipes: [docs/exposure.md](docs/exposure.md).
Spec: [SPEC-EXPOSURE.md](SPEC-EXPOSURE.md).

Release history: [CHANGELOG.md](CHANGELOG.md). Build log and roadmap: [PROGRESS.md](PROGRESS.md).

Evidence handling, retention and governance: see [EVIDENCE-POLICY.md](EVIDENCE-POLICY.md).

## Multi-agent

One binary, thin adapters (see `ADAPTERS.md`):

- **Claude Code plugin** — `claude plugin marketplace add gleicon/secskills`, then
  `claude plugin install secskills@secskills` (skills incl. `/secskills-intake`).
- **Claude Code MCP** — `claude mcp add secskills -- secskills mcp`.
- **opencode** — `AGENTS.md` + `.opencode/command/secskills.md`, or `opencode.json` MCP.
- **Any MCP client** — `secskills mcp` (JSON-RPC 2.0 stdio). Read-only tools:
  `doctor`, `kb_list`, `kb_get`, `recipes_get`, `source_scan`, `fetch`. Live
  `discover`/`test` are never exposed over MCP.

## Install

```bash
go install github.com/gleicon/secskills/cmd/secskills@latest   # Go 1.26+
secskills doctor        # what optional tools you have; --category report checks the PDF browser
```

Or download a static binary (linux/darwin amd64+arm64, windows amd64) from the
[latest release](https://github.com/gleicon/secskills/releases/latest) and check
it against `SHA256SUMS`:

```bash
grep ' secskills-linux-amd64$' SHA256SUMS | sha256sum -c -
```

From a checkout: `make install` (same as `go install ./cmd/secskills`), `make build`
for a local `./secskills`, `make test` for unit + golden CLI tests, `make dist`
for every release binary plus checksums.

Runtime tools are optional (graceful degradation) — see [`INSTALL.md`](INSTALL.md)
or the [install page](https://gleicon.github.io/secskills/install.html).
Headless Chrome/Chromium is needed only for PDF and screenshots.

## Documentation

- Website: <https://gleicon.github.io/secskills/> — [install](https://gleicon.github.io/secskills/install.html), [usage](https://gleicon.github.io/secskills/usage.html), [common cases](https://gleicon.github.io/secskills/cases.html), [safety](https://gleicon.github.io/secskills/safety.html)
- [Getting started](docs/getting-started.md)
- [Usage & commands](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Reporting & compliance](docs/reporting.md)
- [Coverage matrix (skills × tools × OWASP × output)](docs/coverage-matrix.md)
- [Exposure mode recipes](docs/exposure.md) · [Headless capture on a VM](docs/offline-vm.md)
- [Changelog](CHANGELOG.md)
- [Security model](SECURITY.md)
- Full command list: `secskills help`

## Safety

- Authorization gate before any target-touching action.
- Non-destructive, rate-limited, scope-confined by default.
- Target output is untrusted data — scanned for prompt injection, never followed.
- Credentialed requests verify TLS; `--insecure-auth` is an explicit opt-out.
- Engagement data stays local and private: the findings store
  (`~/.secskills-findings/`) and per-target workdirs (`<user cache dir>/secskills/<target>`)
  are owner-only; a symlinked or foreign-owned workdir is refused. Treat them like
  a credentials store; never commit engagement data.
- Report problems in secskills privately to the maintainer (see [SECURITY.md](SECURITY.md)).

## License

- Code (`cmd/`, `internal/`, `skills/`, `lib/`, `tools/`, `*.go`, `rules/`): **MIT** — see [`LICENSE`](LICENSE).
- Knowledge base (`kb/`): OWASP Cheat Sheet Series / Top 10, **CC BY-SA 4.0** —
  see [`LICENSE-OWASP.md`](LICENSE-OWASP.md).

The repository is dual-licensed by path, which is why GitHub shows the license
as "other".

## Legal

secskills tests systems. Only run it against targets you are **authorized** to
test. The authorization gate is a control, not legal cover — you are responsible
for having written permission.
