# Network mode: design

How secskills assesses a network block (an ASN or CIDR you are authorized to
test). Requirement and decision IDs are kept because the code cites them.
Operator guide: [`docs/guides/scan-network-block.md`](docs/guides/scan-network-block.md); the engine spec
is [`SPEC.md`](SPEC.md).

---

## 1. Problem

For the owner of a network block, the useful questions are:

1. What is listening across the block?
2. Where are files, panels, or datastores exposed without authentication?
3. Which running versions fall inside a known CVE range, and which of those
   CVEs are being exploited?
4. After changes, what was fixed and what came back?

A CVSS-sorted list of thousands of rows answers none of these. Network mode
produces a short, ranked set of findings in the same store and report as an
app assessment.

## 2. Scope

What it does:

- ASN → announced prefixes → IP inventory, or an explicit CIDR.
- External, non-destructive observation of each IP: reachable ports, banners,
  product, version, CPE.
- Read-only checks for exposed `.git`, `.env`, `server-status`, directory
  listings, and unauthenticated Redis and Elasticsearch; an optional, double-gated
  vendor-default-credential check for datastores.
- Vulnerability intelligence from CISA KEV, FIRST EPSS, and NVD version ranges,
  cached locally.
- Findings written to the same findings store as app assessments, so report,
  retest, tickets, export, override, and attest work unchanged.

What it does not do:

- Exploitation, denial of service, brute force, or any state change on a host (D-4).
- Patch-state claims from external data. A banner version inside a CVE range is
  a lead to validate, because distributions backport fixes (§6).

## 3. Design choices

| Alternative | Choice | Why |
|---|---|---|
| A separate report and finding model for blocks | Ordinary findings in the main store | One report, one retest, one export path |
| One finding per (host, CVE) | One finding per service, listing its CVEs | A CVE list per service is one decision; thousands of rows are none |
| Re-scan to re-evaluate | Re-join stored observations against newer feeds | Intelligence changes daily; the network does not need to be touched |

## 4. Requirements

### Functional

- **FR-1 Inventory.** Resolve an ASN's announced prefixes (RIPE Stat, IRR
  fallback; cached with a TTL and diffed) or take a CIDR, and enumerate IPs.
  Blocks wider than /20 are refused without `--allow-large`. (`discover --asn/--cidr`)
- **FR-2 Observation.** For each reachable `(ip, port)`, store an observation with
  `source`, `confidence`, and a content fingerprint. `enrich` adds banner,
  product, version, and CPE.
- **FR-3 Intelligence ingest.** Idempotent ingest of KEV, EPSS, and NVD ranges
  into a local cache; each KEV change writes a delta record. (`feed kev|epss|nvd`)
- **FR-4 Matching.** Deterministic join of NVD affected ranges with observed
  product/version. (`cvematch`)
- **FR-5 Findings.** `leakcheck`, `dbcheck`, and `cvematch` write findings with
  stable IDs (`NET-LEAK-…`, `NET-DB-…`, `NET-CVE-…`) and save a run. A re-run
  updates findings in place; a finding the re-run no longer produces closes as
  mitigated; one that returns reopens as regressed; `accepted` and `manual`
  decisions are kept.
- **FR-6 Scoring.** CVE candidates carry a score and its named terms (§10).
  Finding severity follows the main severity rubric (§11).

### Non-functional

- **NFR-2 Rate.** Sweeps and probes are rate-gated in the engine
  (`SECSKILLS_RATE`, default 5 per second).

### Acceptance checks

- **AC-1** A block runs end to end — sweep, enrich, checks, CVE join — and its
  findings render in `report`, `tickets`, and `export`. (golden test)
- **AC-5** A re-run after an upgrade closes the lead that no longer matches,
  without scanning. (golden and unit tests)
- **AC-7** Killing a sweep leaves no partial record, and the sweep resumes.
  (append-only store, tested)

## 5. How a block is addressed

The block, written as given to `discover` (`203.0.113.0/24`, `AS64500`), is the
target name for every command: it selects the workdir and the findings store.

```
secskills discover --cidr 203.0.113.0/24 --confirm
secskills enrich    203.0.113.0/24 --confirm
secskills leakcheck 203.0.113.0/24 --confirm
secskills cvematch  203.0.113.0/24
secskills report --render 203.0.113.0/24
```

`--workdir` overrides the directory, for a capture carried from another machine.
Authorization is checked per IP; `out_of_scope` entries are never scanned.

## 6. Confidence

| Tier | Method | Claim it licenses |
|---|---|---|
| L0 | Cached observation, no traffic | "this port was reachable" |
| L1 | Single non-destructive probe or banner version | "this service runs version X", "this path is served" |

Rule (D-3): external evidence never claims a host is patched or vulnerable.
CVE matches are findings with validation `version-inferred`.

| Question | External observation |
|---|---|
| Is this port reachable from the internet? | yes |
| Which product and version? | usually (banner) |
| Is the kernel or base image patched? | **no** |

## 7. Capture here, process elsewhere

Network-facing steps (`discover`, `enrich`, `leakcheck`, `dbcheck`) can run on a
machine near the target; `deploy/capture.sh` packages the workdir, including the
findings already written. `deploy/process.sh` runs `cvematch` and the report
offline against a feed cache. `plan --asn … --shards N` splits a large block
across capture machines.

## 8. Feeds

### 8.1 Sources

| Source | Used for | Cost |
|---|---|---|
| CISA KEV (JSON) | exploited-in-the-wild flag, delta record | free |
| FIRST EPSS (API) | exploit probability, cached per day | free |
| NVD 2.0 | CPE version ranges and CVSS per product | free (rate-limited) |
| RIPE Stat / IRR | ASN → prefixes, drift | free |

NVD ranges are fetched per product (`feed nvd --product openssh`) for the
products in the CPE map. Feeds are target-independent: fetch once into
`~/.secskills/feed` (or `$SECSKILLS_FEED`) and share the cache read-only across
capture machines.

### 8.2 Re-running without re-scanning

Observations are durable. Refreshing feeds and re-running `cvematch`
re-evaluates every service without touching the network.

## 9. No model on the decision path

There is no LLM call in network mode. Matching, scoring, and remediation text are
deterministic, so every result is reproducible.

## 10. Scoring

```
score = 0.6 × (0.5·KEV + 0.3·EPSS + 0.2·CVSS/10)
```

`0.6` is the L1 confidence; `KEV` is 1 when the CVE is listed. Candidates are
written to `candidates.jsonl` with their `score_terms`; within a finding, CVEs
are listed KEV first, then by score.

## 11. Findings

| Source | Finding | Detector | Severity (rubric) | Retest |
|---|---|---|---|---|
| Exposed `.git`, `.env`, `server-status`, listing | `Exposed path: …` | `http.exposure-path@1` | MEDIUM; potential HIGH when credential-like keys are exposed | re-fetch, pattern still served? |
| Unauthenticated Redis / Elasticsearch | `Unauthenticated …` | `datastore.unauthenticated@1` | HIGH | re-run `leakcheck` |
| Datastore accepts a vendor default credential | `… accepts a vendor default credential` | `datastore.unauthenticated@1` | HIGH | re-run `dbcheck` |
| Banner version in NVD ranges | `Potentially vulnerable <product> version <v> …` | `component.banner-nvd-range@1` | LOW; MEDIUM when a listed CVE is in KEV | re-run `enrich` + `cvematch` |

Credential values are never recorded; only key names and the fact of exposure.
The report adds a network inventory (hosts, services, reachable datastores)
whenever the workdir holds observations.

## 12. Safety

- **Ownership is not authorization.** Announcing a prefix does not authorize
  testing every host in it. Capture commands need `--confirm` or a scope file.
- **Per-IP authorization**, with `out_of_scope` honored even under `--confirm`.
- **Default-credential checks** need `--confirm` and `--intrusive-confirm`, and use
  a short fixed vendor list, never a wordlist.
- **Rate limits** are enforced in the engine (NFR-2).
- **Workdirs** are private to the operator and refused if symlinked or foreign-owned.

## 13. Decision log

| # | Decision | Rationale |
|---|---|---|
| D-1 | External-only; no cloud control plane | Public data only; no privileged inventory needed |
| D-2 | Exposure is computed from observation paths, not asset type | Matching stays independent of cloud entities |
| D-3 | External evidence never asserts patch state | Distro backports keep upstream versions |
| D-4 | No exploit, race trigger, or fault injection | Ethical floor; avoids DoS on target hosts |
| D-5 | KEV is a lagging signal; EPSS ranks the rest | Exploitation often precedes KEV listing |
| D-6 | No LLM in the pipeline | Cost, auditability, determinism |
| D-7 | Observations as JSONL in a workdir; findings in the main store | Append-only, resumable, portable; one report path |

## 14. How it was built

- **N-1** ASN / CIDR input for `discover`, with per-IP scope and the /20 cap.
- **N-2** The probe layer as an embeddable package (`internal/probe`), with an
  append-only, content-addressed observation store and a connect-time
  anti-rebinding guard. `examples/embed` shows library use.
- **N-3** Enrichment, feeds, and the CVE join, later merged into the main
  findings store and report.
