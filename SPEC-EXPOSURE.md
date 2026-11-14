# Exposure mode: design

This document describes how secskills' exposure mode works as built: ASN- or
CIDR-scoped, external-only exposure intelligence. It records requirements and
decisions by ID because the code cites them. Operator recipes are in
[`docs/exposure.md`](docs/exposure.md); the engine spec is [`SPEC.md`](SPEC.md).

---

## 1. Problem

CVE publication volume has outgrown triage. Several failure modes follow:

1. **Patch lag is invisible.** A fix exists upstream, but the host's distro,
   image, or reboot state is unknown.
2. **Exposure is not modelled.** A CVSS 9.8 on an internet-reachable service and
   the same CVE behind a private network are the same row in a scanner report.
3. **Lists are not decisions.** A CVSS-sorted list of thousands of rows is
   operationally equal to zero rows for a team without a security hire.

Exposure mode answers one question for the owner of a network block: **which of
my assets are exposed to something being exploited, and what do I change today?**

## 2. Scope

What exposure mode does:

- ASN → announced prefixes → IP inventory, or an explicit CIDR.
- External, non-destructive observation of each IP: reachable ports, banners,
  product, version, CPE.
- Vulnerability intelligence from CISA KEV, FIRST EPSS, and NVD 2.0 version
  ranges, cached locally, with a delta journal.
- Deterministic matching of affected ranges against stored observations.
- A confidence tier on every candidate, a score with named terms, a finding
  lifecycle, per-tenant feeds, and a one-screen brief.

What it does not do:

- Cloud control-plane integration (inventory, flow logs, security groups).
- Exploitation, denial of service, brute force, or any state change on a host,
  at any tier (D-4).
- Kernel or image patch verification from external data. External tiers report
  "unknown", never "vulnerable" or "patched" (§6.2).

## 3. Design choices

| Alternative | Choice | Why |
|---|---|---|
| Inventory from a cloud control plane | ASN + external observation only | Works for any network owner with public data only |
| `Asset` from VM/bucket entities | `Asset` from `(ip, port)` observations | The matcher never depends on provider entities |
| Vulnerability = CVE with CPE ranges | CVE **plus distro release state** where known | Upstream semver is not actionable when distros backport (§7) |
| Report is a document | JSON + a one-screen brief + Markdown report | The consumer is an agent or an on-call engineer |

## 4. Requirements

### Functional

- **FR-1 Inventory.** Resolve an ASN's announced prefixes (RIPE Stat, IRR
  fallback; cached with a TTL and diffed) or take a CIDR, and enumerate IPs.
  Blocks wider than /20 are refused without `--allow-large`. (`discover --asn/--cidr`)
- **FR-2 Observation.** For each reachable `(ip, port)`, store an observation with
  `source`, `confidence`, and a content fingerprint. `enrich` adds banner,
  product, version, and CPE. (`observations.jsonl`, `enriched-observations.jsonl`)
- **FR-3 Intelligence ingest.** Idempotent ingest of KEV, EPSS, and NVD ranges
  into a local cache. Each KEV change writes a `vuln.updated` delta.
  (`feed kev|epss|nvd`)
- **FR-4 Matching.** Deterministic join of affected ranges with observed
  product/version, emitting candidates with the matching rule and the confidence
  of the observation. (`cvematch`, `match`)
- **FR-6 Scoring.** Every candidate carries a score and the named terms that
  produced it (§10).
- **FR-7 Lifecycle.** `open → confirmed → accepted_risk → fixed → false_positive`,
  with regression and re-triage edges. `lifecycle reconcile` closes a finding as
  fixed when its candidate disappears from a fresh snapshot and reopens it if it
  returns. Human states are preserved. (`lifecycle`)
- **FR-8 Delivery.** A per-tenant JSON feed (mode 0600), a one-screen brief, and
  an optional HTTPS webhook. (`deliver`)
- **FR-9 Fleet intelligence.** Anonymised, counts-only ranking of CVEs and stacks
  across tenants with k-anonymity suppression. (`fleet`)

### Non-functional

- **NFR-1 Latency.** `notify` measures event → notification latency for a KEV
  delta or synthetic event against a budget (default 1 h) without scanning, and
  fails when it is exceeded.
- **NFR-2 Rate.** Sweeps and probes are rate-gated in the engine
  (`SECSKILLS_RATE`, default 5 per second).
- **NFR-3 Tenancy.** Every tenant read goes through one filter on the tenant's
  prefixes; a cross-tenant leak is a test failure.

### Acceptance checks

- **AC-1** A block sweeps end to end: prefixes → observations → candidates →
  findings → brief. Observations and findings carry timestamps.
- **AC-2** A synthetic KEV event notifies the right tenant with the right asset
  within the budget, with no scan. (`notify --kev-event`, tested)
- **AC-3** The CVE-2026-98432 fixture replays to three distinct outcomes at three
  tiers and never claims a vulnerable kernel from external data. (`match`, tested)
- **AC-4** `precision` measures precision against a labelled set and fails below
  90 % or under 100 labelled hosts. The labelled corpus is supplied by the
  operator; `testdata/precision/labels.example.jsonl` documents the schema.
- **AC-6** A cross-tenant read returns nothing. (tested)
- **AC-7** Killing a sweep leaves no partial record, and the sweep resumes.
  (append-only store, tested)

## 5. Two ways to run

secskills is one binary with one contract.

### Mode A: an operator with a CLI or agent

```
human → agent or shell → secskills CLI → target
```

The human holds authorization: `--confirm`, or a trusted `.secskills-scope.yml`
that may list CIDRs. Authorization is checked per IP.

### Mode B: an unattended worker with a signed scope token

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

`secskills token verify` checks the HMAC signature (`SECSKILLS_TOKEN_KEY`) and
refuses any IP outside `prefixes`, any class outside `allowed_classes`, any time
outside the window, and **any** intrusive token regardless of signature (D-4,
D-8). Issuing and scheduling tokens is the orchestrator's job and is not part of
secskills.

## 6. Detection ladder

### 6.1 Tiers

| Tier | Method | Confidence | Urgent feed? |
|---|---|---|---|
| L0 | Cached observation + advisory metadata, no traffic | `low` | only if KEV **and** an exact product/version match |
| L1 | Single non-destructive probe or banner version | `medium` | yes, labelled |
| L2 | Template check with recorded evidence | `high` | yes |
| L3 | Host-reported package/kernel state, supplied as asset input | `verified` | yes; the only tier that may say patched or unpatched |

The exposure pipeline produces L0 and L1. L3 applies only when asset data
includes host-reported state (as in the fixture); secskills does not collect it.

Rule (D-3): **the feed sorts by tier first, score second.**

### 6.2 What external observation can and cannot see

| Question | External | Host data |
|---|---|---|
| Is this port reachable from the internet? | yes | — |
| Which product and version? | usually (banner) | yes |
| Which distro release? | rarely, low confidence | yes |
| Is the kernel patched? | **no** | yes |
| Is the container base image patched? | **no** | yes |

Kernel- and image-level CVEs are reported as *"exposure unknown"*.

### 6.3 Never

- Send a race trigger, exploit, or malformed packet sequence designed to fault a kernel.
- Probe a host outside the token or scope, including redirect targets.
- Infer patch state from a version string alone when distros backport.

## 7. Worked example: CVE-2026-98432 (the regression fixture)

A CVSS 9.8 remote use-after-free in the Linux IPv4 TCP handshake, fixed upstream
per stable line, partially fixed by distros, **not in KEV**. It is the archetype
for "the matcher must be smarter than KEV".

| Fact | Consequence |
|---|---|
| Fixed per stable line (5.10.272, 5.15.223, 6.1.190, …) | The affected range is a tree of per-line fixes, not one threshold |
| Distros backport under their own versions | Distro state is stored per `(cve, distro, release, package)` (D-9) |
| Reachable before application auth, on any listening IPv4 TCP port | Exposure means "any reachable TCP port" |
| The public PoC needs a multipath TCP listener | MPTCP capability is a risk multiplier worth probing for |
| Not in KEV | Distro patch lag and EPSS matter before KEV lists it (D-5) |

The fixture in `testdata/cve-2026-98432/` holds the advisory, four distro
snapshots, and four assets. `secskills match` replays it to: an L3 candidate for
the host-reported asset, an L1 MPTCP-exposed candidate with kernel state
unknown, an L0 generic-Linux candidate, and no candidate for Windows.

### 7.3 Single-packet probes

| Probe | Packets | Claim it licenses |
|---|---|---|
| `tcp.mptcp-capable` | 1 SYN with MP_CAPABLE | "a multipath TCP listener is reachable" |
| `tcp.ipv4-options-echo` (Linux) | 1 SYN with Record Route | "the IPv4-option handshake path is reachable" — reachability only |

No payload, no race attempt, no fault injection (D-4). (`kprobe`)

## 8. Feeds and cache

### 8.1 Sources

| Source | Used for | Cost |
|---|---|---|
| CISA KEV (JSON) | exploited-in-the-wild flag, delta journal | free |
| FIRST EPSS (API) | exploit probability, cached per day | free |
| NVD 2.0 | CPE version ranges and CVSS per product | free (rate-limited) |
| RIPE Stat / IRR | ASN → prefixes, drift | free |

Feeds are target-independent: fetch once into `~/.secskills/feed` (or
`$SECSKILLS_FEED`) and share the cache read-only across workers.

### 8.2 Re-running without re-scanning

Observations are durable. Refreshing feeds and re-running `cvematch` and
`lifecycle reconcile` re-evaluates every asset without touching the network.

## 9. No model on the decision path

There is no LLM call anywhere in exposure mode (D-6). Matching, scoring, and
remediation text are deterministic, so cost does not grow with assets × CVEs and
every result is reproducible. Advisory text and banners are data; target-derived
strings are neutralized before they reach output.

## 10. Scoring

```
score = 0.6 × (0.5·KEV + 0.3·EPSS + 0.2·CVSS/10)
```

`0.6` is the L1 confidence. `KEV` is 1 when the CVE is listed. Each term is
stored in `score_terms`. Candidates sort KEV-urgent first, then by score.

## 11. Output

### 11.1 Candidate (JSON line in `candidates.jsonl`)

```json
{
  "asset_ip": "203.0.113.10",
  "cve": "CVE-2024-6387",
  "tier": "L1",
  "confidence": "medium",
  "patch_state": "unknown",
  "claim": "OpenSSH 8.9p1 is within the affected range of CVE-2024-6387 (>= 8.5p1, < 9.8p1) — version-inferred, confirm against distro backports",
  "remediation": "",
  "urgent_feed": false,
  "score": 0.2763,
  "score_terms": {"confidence": 0.6, "cvss": 8.1, "epss": 0.995, "kev": 0}
}
```

### 11.2 Tenant feed

`feed-<tenant>.json`: `tenant`, `asn`, `generated_at`, `count`, `urgent_count`,
and the tenant's candidates, KEV-urgent first.

### 11.3 Brief (one screen)

```
Exposure brief — tenant acme (AS64500)  <time>
5 candidates, 2 KEV-urgent. Version-inferred (L1): confirm before action.

KEV 203.0.113.10     CVE-2023-44487   epss=0.940 score=0.559
KEV 203.0.113.20     CVE-2023-44487   epss=0.940 score=0.559
    203.0.113.10     CVE-2024-6387    epss=0.995 score=0.276
```

## 12. Safety, authorization, isolation

- **Ownership is not authorization.** Announcing a prefix does not authorize
  testing every host in it. Active checks require written authorization and
  `--confirm`, a scope file, or a scope token.
- **Per-IP authorization.** `out_of_scope` entries are never scanned, even under
  `--confirm`.
- **Rate limits** are enforced in the engine (NFR-2).
- **Tenant isolation** is a single filter on prefixes, covered by a test (NFR-3).
- **Workdirs** are private to the operator and refused if symlinked or
  foreign-owned.

## 13. Decision log

| # | Decision | Rationale |
|---|---|---|
| D-1 | External-only; no control plane | Public data only; no privileged inventory needed |
| D-2 | Exposure is computed from observation paths, not asset type | Matching stays independent of cloud entities |
| D-3 | Tier gates the feed; score sorts within a tier | A 9.8 guess must never outrank a verified finding |
| D-4 | No exploit, race trigger, or fault injection, at any tier | Ethical floor; avoids DoS on target hosts |
| D-5 | KEV is a lagging signal; EPSS ranks the rest, and distro state is used where supplied | Exploitation often precedes KEV listing |
| D-6 | No LLM in the pipeline | Cost, auditability, determinism |
| D-7 | JSONL files in a workdir, no database | Append-only, resumable, portable, diffable |
| D-8 | Tokens, not shell strings, authorize unattended scans | Machine-verifiable scope; same gate as `--confirm` |
| D-9 | Distro state is stored per `(cve, distro, release, package)` | Backports break semver reasoning |
| D-10 | The brief is one screen + JSON, never a PDF | The consumer is an agent or an on-call engineer |

## 14. How it was built

- **N-1** ASN / CIDR input for `discover`, with per-IP scope and the /20 cap.
- **N-2** The probe layer as an embeddable package (`internal/probe`), with an
  append-only, content-addressed observation store and a connect-time
  anti-rebinding guard. `examples/embed` shows library use.
- **N-3** The deterministic matcher (`internal/intel`), the CVE-2026-98432
  fixture, feeds, enrichment, CVE join, lifecycle, precision gate, delivery,
  notification latency, and fleet aggregation.
