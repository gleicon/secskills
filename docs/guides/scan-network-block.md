# Scanning a network block (ASN or CIDR)

Sweep a block you own or are authorized to assess, find what is exposed, and
rank CVE leads — from one /24 up to a whole ASN. Results are **ordinary
findings**: `report`, `report --retest`, `tickets`, `export`, `override`, and
`findings set` work on a block exactly as on a domain. Design: `SPEC-NETWORK.md`.

## Before you start

- Written authorization covering the block. Owning an ASN is not authorization
  to test every host in it: customer or third-party hosts may live there.
- A machine with a stable connection to the block. For large sweeps, see
  [capture-offline.md](capture-offline.md).
- Nothing else: the sweep is a native, rate-gated TCP connect scan.

## 1. Size the job

```bash
secskills plan --asn AS64500 --shards 1 --out ./plan
cat plan/plan.json                     # prefixes and address counts, no traffic to the block
```

`plan` resolves the ASN's announced prefixes (RIPE Stat, IRR fallback) and
counts addresses. A /24 is 256 addresses; a busy ASN can be tens of thousands.
A prefix wider than /20 is skipped unless you pass `--allow-large`.

Announced prefixes are often nested (a /21 and the /22, /23, /24 inside it).
`discover`/`plan` collapse them to their outermost cover before sweeping and
print `N prefixes … M after collapsing overlaps`, so each host is scanned once
rather than once per covering prefix.

## 2. Write the scope

```yaml
# .secskills-scope.yml
engagement: network-q4
authorized: true
confirmed_by: you@example.org
expires: 2026-12-31
targets:
  - 203.0.113.0/24
  - 198.51.100.0/24
out_of_scope:
  - 203.0.113.250                     # never scanned, even under --confirm
```

```bash
chmod 600 .secskills-scope.yml && secskills scope --validate
```

Authorization is checked for every IP, so a sweep of `--asn` only touches
addresses inside `targets`.

## 3. Start small, then widen

Run one prefix end to end first to check rates, timeouts, and what the block
looks like:

```bash
secskills discover --cidr 203.0.113.0/24
secskills enrich    203.0.113.0/24
secskills leakcheck 203.0.113.0/24
```

Then the whole ASN, or each prefix in turn:

```bash
secskills discover --asn AS64500     # every announced prefix; IPs outside the scope are skipped
```

The sweep is append-only and resumable: stop it and run the same command again
without losing what was recorded (it reads back `observations.jsonl`), so raising
the rate mid-engagement costs nothing.

**Throughput.** `SECSKILLS_RATE` (requests/second, default 5) is the bottleneck,
not the machine or the link — one rate-gated process does the same 5 req/s
anywhere. The default is deliberately gentle: a whole ASN of tens of thousands of
addresses takes many hours at 5. Two ways to go faster:

- **Raise the rate on one machine:** `SECSKILLS_RATE=25 secskills discover --asn
  AS64500 --confirm --workers 50`. Roughly linear — 5→25 is about 5× faster.
- **Shard across machines** (see [capture-offline.md](capture-offline.md)): each
  host runs a slice with its own rate gate, so N hosts give N× throughput.

Raise the rate in steps (25, then 50) on a block carrying live services, and
watch for complaints: a higher rate hits your own production harder and in
parallel. Lower both `SECSKILLS_RATE` and `--workers` for fragile networks.

Each block, as written to `discover` (`203.0.113.0/24`, `AS64500`), is a target
with its own workdir and findings store; use the same name in every later command.

## 4. Load intelligence (no traffic to the block)

```bash
secskills feed kev
secskills feed epss
secskills feed nvd --product openssh
secskills feed nvd --product nginx
secskills feed nvd --product apache
```

NVD ranges are fetched per product. `enrich` prints the products it saw; fetch
those. The cache lives in `~/.secskills/feed` (or `$SECSKILLS_FEED`) and can be
shared read-only between machines.

## 5. Match versions to CVEs, offline

```bash
secskills cvematch 203.0.113.0/24
```

Each service whose banner version falls inside an NVD range becomes one finding
listing its CVEs, KEV-listed ones first, then by EPSS. To keep a service that
matches hundreds of ranges from burying the confirmed leaks, each service keeps
its KEV-listed CVEs plus the top non-KEV by score; raise or lift the cap with
`--max-cves N` (`0` = all, default 10).

**What `cvematch` cannot see.** It keys on the version `enrich` reads from a
service banner, so it only covers CVEs in software that *announces a version on
the wire* — SSH, some web servers, some mail daemons. It misses:

- **Application-runtime CVEs.** A bug in a language runtime or app framework
  (for example an OpenJDK or deserialization RCE) lives in a code path, not a
  listening-port banner. The runtime's patch level is never advertised, proxy or
  not, so a network sweep will not attribute it per host. Confirm those host-side
  (`java -version`, package inventory) or with an app-layer test, not here.
- **Backported fixes.** A distribution can patch a CVE without changing the
  version string, so a match is a *lead*, not a confirmed vulnerability — the
  report labels these `version-inferred`. Verify the running build before acting.

## 6. Optional: default credentials on datastores

Only with the owner's explicit approval:

```bash
secskills dbcheck 203.0.113.0/24 --confirm --intrusive-confirm
```

A short fixed list of vendor defaults for Redis, Elasticsearch, and MySQL, and an
unauthenticated check for MongoDB. Never a wordlist; no data is read beyond one
liveness command.

## 7. Triage

```bash
secskills report --render 203.0.113.0/24      # findings + network inventory
secskills findings show 203.0.113.0/24
```

Work in this order:

| Priority | Finding | Severity | Why |
|---|---|---|---|
| 1 | Unauthenticated or default-credential datastore | HIGH | data is reachable now |
| 2 | Exposed `.env` (credentials) or exposed `.git` (source + history) | HIGH | secrets and source are reachable unauthenticated |
| 3 | CVE lead with a KEV-listed CVE | MEDIUM | exploited in the wild |
| 4 | Other CVE leads, by EPSS | LOW | version-inferred; validate first |
| — | Datastores reachable at all (inventory section) | — | they should not face the internet |

CVE leads come from banners: a distribution can fix a CVE without changing the
version string. Confirm the running build before scheduling an emergency patch.
Record your decisions:

```bash
secskills findings set --target 203.0.113.0/24 --id NET-CVE-203.0.113.10:22 \
  --status accepted --note "fixed via distro backport, verified on host"
secskills override --target 203.0.113.0/24 --key <finding_key> --severity LOW --reason "…"
```

Hand off:

```bash
secskills report --pdf 203.0.113.0/24 --output block.pdf
secskills tickets 203.0.113.0/24 --format csv --output block.csv
secskills export --format sarif 203.0.113.0/24 --output block.sarif
```

## 8. Every week

```bash
secskills feed kev && secskills feed epss
secskills cvematch 203.0.113.0/24                 # no traffic: re-join against new intelligence
secskills report --retest 203.0.113.0/24          # re-probe exposed paths
```

Leads that no longer match close as fixed; returning ones reopen as regressed;
`accepted` decisions are kept. Re-run `discover`, `enrich`, and `leakcheck`
monthly, or after network changes, to refresh what is listening.

## What becomes a finding

| Observed | Finding ID | Detector |
|---|---|---|
| `.git`, `.env`, `server-status`, directory listing | `NET-LEAK-<ip:port>-<kind>` | `http.exposure-path@1` |
| Unauthenticated Redis / Elasticsearch | `NET-LEAK-<ip:port>-<kind>` | `datastore.unauthenticated@1` |
| Default credential accepted | `NET-DB-<ip:port>` | `datastore.unauthenticated@1` |
| Banner version in NVD ranges | `NET-CVE-<ip:port>` | `component.banner-nvd-range@1` |

## Commands

| Command | Touches the block | Gate | Produces |
|---|---|---|---|
| `plan --asn` | no (RIPE/IRR only) | — | `plan.json`, `shard-<i>.txt` |
| `discover --cidr/--asn` | yes | `--confirm` or scope | `observations.jsonl` |
| `enrich <block>` | yes | `--confirm` or scope | `enriched-observations.jsonl` |
| `leakcheck <block>` | yes | `--confirm` or scope | findings, `leaks.jsonl` |
| `dbcheck <block>` | yes | `--confirm --intrusive-confirm` | findings, `dbcheck.jsonl` |
| `feed kev\|epss\|nvd` | no | — | feed cache |
| `cvematch <block>` | no | — | findings, `candidates.jsonl` |
| `findings import <block>` | no | — | findings from merged captures |

## Pitfalls

- Don't run `--asn` before checking the plan: it expands to every announced prefix.
- Don't point `SECSKILLS_WORKDIR` at a shared directory; the default is private.
- A host that drops connections under load looks closed. If a sweep finds less
  than expected, lower `SECSKILLS_RATE` and `--workers` and re-run; it resumes.
