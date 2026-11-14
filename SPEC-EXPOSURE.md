# Specification: exposure mode v0 (ASN-scoped exposure intelligence)

Status: **draft for build** · 2026-11-02
Companion docs: `SPEC.md` (secskills engine), `docs/architecture.md`, `docs/exposure.md`

---

## 1. Problem

CVE publication volume has outgrown triage. October 2026 alone: **17,060 CVEs** (vs 4,274 in
October 2025 — a 4× year, ~560/day). AI-assisted discovery is now producing working exploit
code in hours, not weeks: CVE-2026-98432's CVE record was published Oct 15 and Anthropic
described a Claude-built remote-root PoC on Oct 27 — 12 days (§7).

The failure mode is not "we don't know about CVEs". It is:

1. **Patch lag is invisible.** A fix exists upstream; the host's distro, image, or reboot
   state is unknown. Ubuntu had no fixed kernel for CVE-2026-98432 for two weeks after upstream.
2. **Exposure is not modelled.** A CVSS 9.8 on an internet-reachable service and the same CVE
   on a host behind a private security group are the same row in a scanner report.
3. **Lists are not decisions.** A CVSS-sorted list of 4,000 rows is operationally equal to zero
   rows for a team without a security hire.

Exposure mode answers one question per network owner, in minutes: **"which of my assets are exposed
right now to something that is being exploited, and what do I change today?"**

## 2. Scope

**In scope (v0)**

- ASN → announced prefixes → IP inventory (no cloud control-plane integration).
- External, non-destructive observation of each IP: ports, banners, TLS, product/version, CPE.
- Intelligence ingestion with deltas: NVD, OSV, GHSA, CISA KEV, EPSS, distro trackers, nuclei
  templates, public-PoC signals.
- Deterministic matching: vulnerability affected-ranges → cached observations.
- Confidence-tiered validation (external observation → protocol probe → template check →
  authenticated agent) with the tier recorded on every finding.
- Priority score, finding lifecycle, re-verification, and an agent-readable output contract.
- Two deployment modes for the detection engine (§5).

**Out of scope (v0)**

- Cloud control-plane integration (inventory, flow logs, security groups). Phase 3.
- A web UI. v0 is a CLI + JSON + MCP + brief.
- Autonomous exploitation, DoS, brute force, credential attacks, or any state change on a
  target host. Never in scope, at any phase (D-4).
- Kernel/OS patch *verification* without an agent or provider telemetry (§6.2). v0 says
  "unknown", not "vulnerable".
- Full OWASP-authenticated testing (that is the engine's Mode A, `SPEC.md`).

**Non-goals we will not drift into**: SIEM, EDR, log retention, compliance reporting suites,
PDF report generation.

## 3. Design choices

| Alternative | v0 decision | Why |
|---|---|---|
| Inventory from a cloud control plane (flow logs, SG state) | ASN + external observation only | Works for any network owner with public data only; the same pipeline upgrades later |
| `Asset` starts from VM/bucket/SG entities | `Asset` starts from `(ip, port)` observations; cloud IDs attach later | The matcher never depends on provider entities, so it survives a phase-3 merge |
| Vulnerability = CVE with CPE ranges | Vulnerability = CVE **plus distro release state** | CVE-2026-98432 proves upstream semver is not actionable (§7.2) |
| Score uses signal from ASN sensors | Signal term starts at `0` and is additive | The score must be honest before the sensors exist |
| Report artifact is a document | Output is JSON + MCP + a 1-screen brief | The consumer is an agent or an on-call dev, not a reader of 30 pages |

## 4. Requirements

### Functional

- **FR-1 Inventory.** Given an ASN (or explicit CIDR list), resolve announced prefixes
  (RIPE Stat / IRR / BGP), enumerate IPs, and persist `network` + `asset` rows with source and
  first/last-seen timestamps. Refuse blocks larger than the configured cap without an explicit
  override.
- **FR-2 Observation.** For each IP, produce a `observation` row: reachable ports, service
  banner, product/version, TLS metadata, HTTP fingerprint, CPE where derivable. Every
  observation carries `source` and `confidence`.
- **FR-3 Intelligence ingest.** Incremental, idempotent ingest of NVD 2.0, OSV, GHSA, KEV,
  EPSS, distro trackers (Ubuntu/Debian/RHEL/SUSE/Oracle/Amazon errata), nuclei template index,
  and POC signals. Every ingest writes a `vuln.updated` event only when content changed.
- **FR-4 Matching.** Deterministic join: affected ranges `(ecosystem, package, distro, release,
  version-range)` × `package`/`cpe` from observations × `exposure`. Emits `candidate` with the
  matching rule and the confidence of the underlying observation.
- **FR-5 Validation.** Each candidate is promoted to `finding` only if it clears the confidence
  policy for its class (§6). Validation methods are recorded, never inferred.
- **FR-6 Scoring.** Every finding carries a score and the **named terms** that produced it, so
  "why is this #1" is answerable without a model.
- **FR-7 Lifecycle.** `open → confirmed → accepted_risk → fixed (re-verified) → false_positive`.
  Re-verification is scheduled, and a fix closes the finding automatically.
- **FR-8 Delivery.** Per-tenant JSON feed, webhook/Slack/email, and an MCP surface. A daily
  brief of at most one screen; no PDF.
- **FR-9 Fleet intelligence.** Aggregate, anonymised ranking of common stacks and
  misconfigurations across tenants.

### Non-functional

- **NFR-1 Latency.** `KEV` or "new CVE-tagged template" → affected tenants notified in **< 1 h**,
  measured p95, with no full re-scan on the path (§8).
- **NFR-2 Rate.** Per-target request budget enforced by the engine, not by convention. A single
  host never exceeds its class budget; a whole /24 sweep respects the global gate.
- **NFR-3 Tenancy.** Every row carries `tenant_id`; all reads are tenant-scoped at the query
  layer. Cross-tenant leakage is a test, not a code review item.
- **NFR-4 Evidence.** Every finding ships an evidence artifact + a replayable command. An
  operator can reproduce the finding without reading code.
- **NFR-5 Cost.** LLM spend is bounded by construction: extraction is cached per advisory, and
  no per-asset LLM call exists on the decision path (§9).
- **NFR-6 Audit.** Every export, view, and agent query is logged with actor and token id.

### Acceptance criteria (v0)

- **AC-1** One ASN sweeps end-to-end: prefixes → observations → candidates → findings → brief,
  with a per-stage timestamp.
- **AC-2** A synthetic KEV event notifies the right tenant with the right asset in < 1 h in the
  lab, without triggering a scan.
- **AC-3** Replaying the CVE-2026-98432 fixture (§7) produces three distinct outcomes at three
  confidence tiers, and never claims "vulnerable kernel" from external data alone.
- **AC-4** Precision measured against a hand-labelled set of ≥ 100 hosts is ≥ 90% before any
  feed is delivered; the corpus and the measurement are committed.
- **AC-5** Every finding exposes `evidence_ref` + `repro_command` that a second operator can run.
- **AC-6** A cross-tenant read attempt fails in tests, including via the MCP surface.
- **AC-7** Killing the scanner mid-sweep leaves no partial finding; the sweep is resumable.

## 5. secskills positioning: two deployment modes

secskills stays one binary and one contract. An orchestrator is one consumer of it; a human with
an agent (Claude Code, opencode, any MCP client) is another.

### Mode A — standalone Claude companion (what exists today)

```
human → Claude/agent → secskills CLI or MCP stdio → target
```

- One target per run, workdir per target, human holds authorization.
- Gate: `--confirm` / trusted `.secskills-scope.yml`.
- Output: findings.json, evidence, report; `retest` for deltas.
- Upgrade needed for v0: ASN/CIDR input (N-1) so the same binary can address a block.

### Mode B — detection worker under orchestration

```
orchestrator (policy, queue, store) → signed scope token → secskills worker → events
```

- The worker receives a **scope token**, not a shell command line:

```json
{
  "tenant": "t_8f2a",
  "asn": 64500,
  "prefixes": ["203.0.113.0/24"],
  "not_before": "2026-11-02T00:00:00Z",
  "not_after":  "2026-11-02T06:00:00Z",
  "max_pps": 40,
  "allowed_classes": ["cve", "web-passive", "tls", "exposure"],
  "intrusive": false,
  "issued_by": "orchestrator",
  "sig": "hmac-sha256:…"
}
```

- The worker verifies the signature and refuses any target outside `prefixes`, any check outside
  `allowed_classes`, any run outside the window, and **any** `intrusive` action regardless of
  token (D-4).
- The worker publishes events (`observation`, `candidate`, `finding`, `error`) and has **no
  access to the findings store** — that isolation is the blast-radius limit.
- The LLM (free agent) may call the read-only surface: query findings, propose a check, draft
  prose. It never holds the token and never triggers a scan.
- This is the same gate as `--confirm`, made machine-verifiable. `--confirm` becomes "the token
  validated" in Mode B; the human path is unchanged.

**Consequence:** every detection primitive must be addressable as `(target, class, budget)` and
returned as data. That is what the probe-package extraction (N-2) buys.

### Capability map

| Need | secskills today | v0 gap |
|---|---|---|
| HTTP/TLS/exposure probes | yes | package it (N-2) |
| Stable finding identity + drift | yes (`observationKey`) | expose as library |
| Evidence + tamper-evident bundle | yes (`captureEvidence`, `attest`) | per-tenant signing key |
| Severity rubric independent of detector | yes (`assessSeverity`) | add `confidence_tier` dimension |
| Validation by template | nuclei, narrow tags | curated CVE template set + quarantine |
| Blind SSRF validation | OAST server | reuse |
| ASN/CIDR input | **no** | N-1 |
| Feed ingest (KEV/EPSS/distro) | **no** | new service |
| Vuln→asset matching at scale | **no** | new service |
| Tenancy, lifecycle at scale | **no** | new service |

## 6. Detection ladder and honest confidence

### 6.1 Tiers

| Tier | Method | Confidence | May appear in the urgent feed? |
|---|---|---|---|
| L0 | Cached observation + advisory metadata (no traffic) | `low` | only if `KEV` **and** product/version match is exact |
| L1 | Single non-destructive protocol probe (banner, TLS, one crafted SYN) | `medium` | yes, labelled |
| L2 | Template check (curated nuclei / native) with recorded evidence | `high` | yes |
| L3 | Authenticated agent (SBOM, kernel package, config) or host telemetry | `verified` | yes, and it is the only tier allowed to say "patched"/"unpatched" |

Rule (D-3): **the feed sorts by tier first, score second.** A CVSS 9.8 at L1 never outranks a
verified exposure, and a tier-`low` kernel guess never enters the urgent feed at all.

### 6.2 What external-only can and cannot see

| Question | External | Agent |
|---|---|---|
| Is this port internet-reachable? | yes (L0/L1) | — |
| Which product/version? | usually (banner/TLS) | yes |
| Which distro release? | rarely, low confidence | yes |
| Is the kernel patched? | **no** | yes |
| Is the container base image patched? | **no** | yes |
| Was this exploited? | signal-dependent | flow/sensor |

**Product-facing rule:** v0's external claim is *"exposed and exploitable from the internet,
validated"*. Kernel and image-level CVEs are reported as *"exposure unknown — agent required"*,
which is honest and is the reason the agent tier exists.

### 6.3 Anti-goals

- Never send a race trigger, exploit, or malformed packet sequence designed to fault a kernel.
- Never probe a host outside the token/scope, including redirect targets and CDN origins.
- Never infer patch state from a version string alone when distro backports exist.

## 7. Worked example — CVE-2026-98432 (the spec's regression fixture)

A CVSS 9.8 remote use-after-free in the Linux IPv4 TCP handshake, fixed upstream Oct 11–18,
partially fixed by distros through Nov 1, **not in KEV** at time of writing. It is the archetype
for "the product must be smarter than KEV".

### 7.1 Facts the model must represent

| Fact | Consequence for the design |
|---|---|
| Affects Linux ≥ 4.4; fixed in 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10, 7.3 | Upstream range is a tree of per-line fixes, not a semver threshold |
| Distros backport under their own versions (RHEL 9.8 `5.14.0-687.64.1.el9_8`; Ubuntu 24.04 `6.8.0-149.149` still "work in progress") | `vuln_range` needs `(distro, release, package)` and the tracker as source of truth |
| Reachable in-kernel before app auth, any listening IPv4 TCP port | Exposure = "any reachable TCP port", not "a web endpoint" |
| Trigger needs IPv4 options (Record Route / Timestamp) in the SYN | A single benign SYN with options tests reachability of the code path |
| Anthropic's working PoC required a **multipath TCP listener**; Go ≥ 1.24 opens MPTCP listeners by default | MPTCP capability is a *risk multiplier* worth probing for — and an externally observable one |
| Not in KEV; 41 GitHub repos, ≥ 7 with race trigger/PoC | PoC-signal and distro-patch-lag must be first-class before KEV exists |
| Interim mitigations: drop TCP packets with `ip hdrlength gt 5`; disable `net.mptcp.enabled` | Remediation is distro-specific; the finding must carry the right one |

### 7.2 Pipeline trace

```
T0  KEV/EPSS delta      → no change (not listed)
T0  CNA record publish  → vuln.published (Oct 15) → extraction needed: CPE absent in NVD
T1  extraction (cached) → affected ranges per stable line + "distro tracker required"
T1  distro trackers     → ubuntu: vulnerable|wip(24.04 6.8.0-149.149) ; rhel: fixed(8,9,10 Nov 1)
                            amazon: fixed ; debian: fixed ; suse: partial ; almalinux: testing
T1  matcher             → for each tenant asset with a reachable TCP port:
                            - asset OS known via agent?  → tier L3 candidate
                            - asset is a Go service (banner/header) → MPTCP likely → multiplier
                            - otherwise → tier L0 candidate, "kernel unknown"
T0/T2 POC signal        → GitHub search count per CVE (cached, rate-limited) → urgency term
L1  probe (1 SYN)       → mptcp-capable? ipv4-options-echo?
L2  template            → none exist for a kernel UAF; **do not fabricate one**
T15 score               → risk = exposed × confidence × (w·PoC + w·patch_lag) × criticality
T15 notify              → "3 hosts likely MPTCP-exposed, kernel unknown — run the agent or the
                            nft rule"  (never "you are vulnerable")
```

### 7.3 New primitives this fixture requires

| Primitive | Packet budget | Method | Claim it licenses |
|---|---|---|---|
| `tcp.mptcp-capable@1` | 1 SYN | SYN with MP_CAPABLE (option 30); SYN-ACK with MP_CAPABLE ⇒ MPTCP listener | "a multipath TCP listener is reachable" — the setup the public PoC needs |
| `tcp.ipv4-options-echo@1` | 1 SYN | SYN with Record Route option; options echoed in SYN-ACK ⇒ vulnerable code path is exercised | "the IPv4-option handshake path is reachable" (reachability only, **not** patch state) |
| `kernel.version-inference@1` | 0 | TTL/stack fingerprint | `INFORMATIONAL`, never in the urgent feed |

Both probes are single packets, no payload, no race attempt, no fault injection (D-4). They are
the difference between "we saw port 22" and "this host is in the highest-risk class for today's
kernel CVE".

## 8. Feed contract, cache, and latency

### 8.1 Sources

| Source | Cadence | Cost | What it gives |
|---|---|---|---|
| CISA KEV (JSON) | hourly delta | free | exploited-in-wild reprioritisation |
| EPSS (FIRST, CSV/API) | daily | free | probability signal + decay |
| NVD 2.0 | delta, 50 req/30 s | free (key) | CPE + CVSS + descriptions |
| OSV (batch) / GHSA | hourly | free | structured affected ranges (skip the LLM) |
| Distro trackers (Ubuntu, Debian, RHEL, SUSE, Oracle, Amazon) | hourly | free | **patch state per distro release** |
| nuclei-templates (git) | hourly | free | ready-made validation for CVE-tagged checks |
| exploit-db / Metasploit (git) | daily | free | PoC presence |
| GitHub search (PoC count) | on candidate only | free (rate-limited) | urgency before KEV |
| Shodan InternetDB | on demand | free, no key | per-IP ports/CPE/vulns for cheap triage |
| GreyNoise | on alert | paid | "known benign scanner" → suppress noise |
| Shadowserver reports | daily | free (network owner) | per-ASN exposure reports sent only to the owner |
| RIPE Stat / IRR / BGP | daily | free | ASN → prefixes, drift |

### 8.2 Cache keys (this is the cost and latency control)

```
observation   : (ip, port, fingerprint_version)
check_result  : (check_id, asset_fingerprint, params_hash)
extraction    : (advisory_id, advisory_hash, prompt_version, model)
poc_signal    : (cve_id, day)
distro_state  : (cve_id, distro, release, package)
```

A check whose inputs are unchanged is never re-executed. A CVE whose advisory hash is unchanged
is never re-extracted. This is what makes "<1 h for KEV" a join, not a sweep.

### 8.3 Latency budget (p95)

| Path | Budget |
|---|---|
| KEV delta → candidate | 5 min |
| candidate → validated finding (L1/L2) | 30 min |
| distro tracker change → affected tenant notified | 60 min |
| new CVE → extraction stored | 30 min (queue, cached) |
| full ASN re-observation | 24 h (background, rate-limited) |

## 9. Token economy

**Three LLM touchpoints, none in the decision path, all content-hash cached.**

| Touchpoint | Granularity | When skipped | Output |
|---|---|---|---|
| Advisory → structured (`product`, `purl/cpe`, ranges, preconditions) | once per CVE | feed already structured (OSV/GHSA, NVD-with-CPE) | schema-validated JSON |
| Check drafting (template/rule) | once per CVE, quarantined | a curated template already exists | rule + fixture, not auto-deployed |
| Client prose | once per finding *template*, not per finding | remediation is a template with parameters | 1 paragraph |

**Budget model.** ~560 CVEs/day. If 40 % lack structured ranges → ~7 k extractions/month at
~3.5 k input + 400 output tokens ≈ 25 M input tokens/month → single-digit to low-double-digit
dollars on a small model. Deterministic matching and templated remediation cost **zero**.

**The forbidden design** (call it out in review): any per-asset or per-(asset × CVE) LLM call.
10 k assets × 500 relevant CVEs = 5 M calls; this is how cost explodes.

**Quality control.** A labelled corpus of 50 advisories (including CVE-2026-98432, where NVD has
no CPE and the ranges live in prose + trackers) is the eval set for extraction. Regression on it
blocks deploy — the same discipline as `conformance`/`measure` in the engine.

**Prompt injection.** Advisories, banners, and fetched pages are data. Structured output +
schema validation + no tool access for the extraction agent. High-risk text is routed through
`secskills scan` before it reaches a model.

## 10. Scoring

```
risk = exposed(0|1)
     × confidence{W:0.3, M:0.6, H:0.9, verified:1.0}
     × ( w_kev·KEV + w_epss·EPSS + w_poc·PoC + w_signal·ASN_signal + w_lag·patch_lag )
     × criticality(asset)
```

- `exposed` comes from the exposure path (internet → port → service), not from the asset.
- `patch_lag` = days since a fix was available for the asset's distro/package (agent or tracker);
  `0` when unknown, never a guess.
- Config and web classes substitute `base_severity(rule)` for the KEV/EPSS terms.
- Every term is stored on the finding (`score_terms[]`), and the weights are versioned.
- Calibration input: operator "false positive" labels adjust `confidence` mapping first,
  weights second, and only with a measured sample.

## 11. Output contract

### 11.1 Finding (JSON)

```json
{
  "id": "fnd_01J…",
  "tenant": "t_8f2a",
  "class": "cve_new | cve_old | web | config",
  "asset": {"ip": "203.0.113.17", "hostname": "api.example", "asn": 64500, "criticality": "high"},
  "vuln": {"id": "CVE-2026-98432", "cvss": 9.8, "kev": false, "epss": 0.31, "poc_signal": 7},
  "exposure": {"reachable": true, "port": 443, "path": "internet→203.0.113.17:443"},
  "evidence": {"tier": "L1", "method": "tcp.mptcp-capable@1", "artifact": "ev_01J…",
               "repro": "nc -vz 203.0.113.17 443  # see artifact for the SYN/option capture"},
  "score": 0.87,
  "score_terms": {"exposed": 1, "confidence": 0.6, "poc": 0.5, "patch_lag": 0.2},
  "claim": "MPTCP listener reachable; kernel patch state unknown",
  "remediation": {"key": "cve-2026-98432.mptcp", "action": "…", "distro": "rhel9"},
  "state": "confirmed",
  "first_seen": "2026-11-02T09:12:00Z"
}
```

### 11.2 MCP surface (read-only, scoped token, audited)

`findings.list`, `findings.get`, `assets.search`, `vuln.status`, `brief.today`,
`checks.propose` (writes to a proposal queue only). No tool may trigger a scan.

### 11.3 Brief (one screen)

```
TODAY · t_8f2a · AS64500 · 3 things
1. 203.0.113.17:443  MPTCP listener reachable, kernel unverified — patch first (CVE-2026-98432)
2. 203.0.113.44:22   OpenSSH 8.9p1, CVE-2026-… KEV, verified by template
3. bucket cx-prod-uploads is world-readable (config) — 2 min fix
Δ vs yesterday: +2 new, -1 fixed (203.0.113.9 verified patched)
```

## 12. Safety, authorization, isolation

- **Ownership ≠ authorization.** Announcing a prefix does not authorize testing every host in it;
  hosts may be run by third parties. Passive work uses public data only. Active checks require
  written authorization + the scope token.
- **Token-scoped scanning** (§5 Mode B): prefixes, window, classes, pps. Out-of-scope = refuse,
  log, alert.
- **Rate limits** are enforced in the engine and observable per tenant; a kill switch exists per
  tenant and globally.
- **Isolation:** workers cannot read the findings store; findings are encrypted per tenant with
  per-tenant keys; human access is break-glass and audited.
- **Abuse handling:** reverse-DNS/abuse contacts, a published scan policy, and a
  `security.txt`-style contact for complaints, per prefix.
- **Prompt injection** is a data-handling problem, not a prompt problem (§9).

## 13. Phases

**Phase 1 (v0, this spec).** ASN → observation → match → score → brief. One tenant, one ASN,
external only. Exit: AC-1…AC-7.
**Phase 2.** Agent (L3): kernel/package inventory, patch lag, auto-close on verified fix.
Exit: "patched/unpatched" claims with evidence.
**Phase 3.** Cloud control plane: VM/image/SG/bucket entities, flow-log and sensor signals,
config-drift alerts on change events.

## 14. Immediate next steps

### N-1 · secskills: ASN / CIDR input mode

**Why now:** v0 has no input path for a block; today `discover` is domain-only.

- `secskills discover --asn AS64500 --confirm` and `discover --cidr 203.0.113.0/24 --confirm`.
- ASN → prefixes via RIPE Stat (`announced-prefixes`), IRR (`whois -i origin`) as fallback, both
  through the existing throttled `fetch` layer; prefixes cached with a TTL and diffed.
- Enumeration: `naabu` when present, native rate-gated TCP connect fallback otherwise; cap at
  /20 unless `--allow-large` is passed explicitly.
- Extend the scope file to accept `asn:` and CIDR entries; the gate validates every IP against
  the effective set (this is the reuse of the Mode-B token idea in the human path).
- Output: `live_hosts.json` gains `asn`, `prefix`, `ip`; `data/asn-<asn>-prefixes.json`.
- Acceptance: an authorized /24 sweeps end-to-end with the rate gate honored; out-of-scope IPs
  refuse; a > /20 request refuses without the override; unit tests for prefix parsing, cache
  diffing, and scope matching.

**Files:** new `asn.go`, `netscan.go`; edits to `mode.go` (flags), `scope.go` (CIDR/ASN
entries), `ratelimit` usage; tests `asn_test.go`, `scope_test.go`.

### N-2 · Extract the probe layer into an embeddable package

**Why now:** an orchestrator must consume detections as a library; spawning a CLI per asset does
not scale to an ASN, and the orchestrator needs `(target, class, budget) → observations`.

- New `internal/probe` package: `Finding`, `Observation`, `evidence`, `httpdo` (SSRF guard,
  bounded read, no redirects), severity rubric, probe entry points by class.
- Keep `package main` compiling with **type aliases** (`type Finding = probe.Finding`) so no
  call site changes in the first step; move detectors class by class afterwards.
- Add `Observation` (ip, port, service, product, version, cpe, tls, source, confidence,
  fingerprint_version) — the engine's first non-finding output type, and the v0 cache unit.
- Acceptance: `go build ./...`, `go vet`, full test suite and `conformance`/`measure` green with
  zero behavioral diff; `internal/probe` has no import of `main`; a tiny `examples/embed` proves
  library use in < 40 lines.

**Files:** new `internal/probe/{probe.go,httpdo.go,severity.go,evidence.go,observe.go}`;
`main` keeps thin wrappers. (As built: the CLI lives in `cmd/secskills`, logic in
`internal/*`, and the probe type aliases in `internal/exposure/aliases.go`.)

### N-3 · One-week spike (external-only, no control plane)

Day 1 · ASN → prefixes → IP list; Shodan InternetDB sweep of one /24 into `observation` cache
(SQLite is enough). Day 2 · KEV + EPSS ingest; join on cached CPE/version **without scanning**;
produce candidates. Day 3 · `httpx` banners on the subset needing confirmation; CPE extraction;
best-effort distro guess with an explicit confidence. Day 4 · the three §7.3 primitives on the
candidates + a curated nuclei subset on the top 20; record evidence. Day 5 · emit the §11 brief
+ JSON; hand-label 50 hosts; measure precision, time-to-candidate, and LLM spend.

**Exit criteria:** a written result with (a) precision on the labelled set, (b) measured latency
from a synthetic KEV event to a candidate, (c) tokens/dollars spent, and (d) a demo of the
CVE-2026-98432 fixture producing tier-labelled outcomes. If precision < 90 %, the gap becomes
the next spec item — not a launch.

**Fixture to commit:** `testdata/cve-2026-98432/` — the CNA record, the four distro tracker
snapshots (ubuntu vulnerable, rhel fixed, amazon fixed, almalinux testing), and the expected
matcher output for four synthetic assets (agent-verified, MPTCP-capable, generic Linux, Windows).

## 15. Decision log

| # | Decision | Rationale | Revisit when |
|---|---|---|---|
| D-1 | v0 is external-only; no control plane | public data only; no privileged inventory needed | Phase 3 |
| D-2 | `exposure` is computed from observation paths, not from asset type | keeps matching independent of cloud entities | never |
| D-3 | tier gates the feed; score sorts within tier | a 9.8 guess must never outrank a verified finding | after 3 months of precision data |
| D-4 | no exploit, no race trigger, no fault injection, at any tier | ethical floor; also avoids DoS on target hosts | never |
| D-5 | KEV is a lagging signal; PoC count + distro patch lag are first-class | CVE-2026-98432 is not in KEV yet | KEV coverage improves |
| D-6 | LLM only at extraction/drafting/prose, cached per advisory | cost + auditability + determinism | if extraction quality blocks v0 |
| D-7 | Postgres with explicit edges, no graph DB | join-heavy, not traversal-heavy | if 3+ hop queries dominate |
| D-8 | tokens, not shell strings, authorize Mode-B scans | machine-verifiable scope; same gate as `--confirm` | never |
| D-9 | distro tracker state is stored per `(cve, distro, release, package)` | backports break semver reasoning | never |
| D-10 | brief is one screen + JSON, never a PDF | consumer is an agent or an on-call dev | never |

## 16. Open questions

1. Authorization evidence for a whole block: what written scope is enough per prefix?
2. GreyNoise/Shodan credits budget per tenant: per-alert enrichment or sampled?
3. Do we expose `checks.propose` to tenant-side agents, or keep proposals internal?
4. Precision measurement: who labels the 100-host set, and how often is it refreshed?
5. ASN scanning policy: per-prefix published contact and rate; needs a template + review.

## 17. Watchlist (revisit triggers for this spec)

- CVE-2026-98432 enters KEV, or Ubuntu/Debian ship fixed kernels, or NVD publishes CPE ranges
  → update the fixture and the extraction eval set.
- The separate IPv6 fix lands → new affected-range row, same CVE family.
- Go changes the MPTCP default (e.g. Go ≥ 1.27) → re-weight the MPTCP multiplier.
- A vendor publishes a safe external detection for a kernel CVE → promote to L2.
- Shadowserver or Censys terms change → re-evaluate the feed table.

## 18. Change log

- **2026-11-02** — initial draft. Encodes CVE-2026-98432 as the acceptance fixture; splits
  secskills into Mode A (standalone companion) and Mode B (token-scoped worker); defines N-1,
  N-2, N-3; adds the tier-gated feed rule (D-3) and the two new single-packet primitives.
