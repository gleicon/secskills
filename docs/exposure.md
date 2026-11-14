# Exposure mode — recipes, use cases, how-tos

Exposure mode is the ASN-scoped external exposure layer of secskills: a wide, cheap
sweep that stores raw service observations, then deterministic joins that turn
those observations into prioritized, administrator-ready findings. It gives the
owner of a network block a continuous automated red team — staying ahead of the
CVE curve instead of chasing it.

The authoritative spec is `SPEC-EXPOSURE.md`. This page is the operator's
guide: what each stage does, and the copy-paste recipes that chain them.

## Mental model

```
ASN/CIDR ─ discover ─▶ observations.jsonl        (wide cheap sweep, the substrate)
                  │
            enrich ─▶ enriched-observations.jsonl (product / version / CPE)
                  │
         leakcheck ─▶ leaks.jsonl                 (exposed .git/.env, unauth stores)
         dbcheck   ─▶ dbchecks.jsonl              (datastore auth posture — gated)
                  │
   feed kev/epss/nvd (OSINT, cached)
                  │
          cvematch ─▶ candidates.jsonl            (version-inferred, KEV+EPSS ranked)
         lifecycle ─▶ findings.jsonl              (state machine, re-verified)
      prefix-report ─▶ <report>.md               (for the asset owner's admins)
```

The **Observation** is the center of gravity, not the Finding. The sweep is cheap
and stores everything it sees; intelligence is a join you can re-run offline, next
week, against a newer feed, without re-touching the network.

## Detection tiers and the honesty invariant

Every candidate carries a tier:

| Tier | Meaning | May assert patch state? |
|------|---------|-------------------------|
| L0 | cached observation | no |
| L1 | single probe / version-inferred | no |
| L2 | template match | no |
| L3 | host-reported package/kernel state, supplied as asset input (secskills does not collect it) | **yes** — only L3 |

External tiers never claim "patched" or "vulnerable": a distro backport can fix a
CVE behind an unchanged version string, so a banner version in an affected range
is a **lead to confirm**, not a finding. This is enforced in code, not convention.

## Use cases

### 1. A prefix, end to end

You are authorized to assess `203.0.113.0/24`. Produce a continuous posture
report for its administrators.

```sh
export SECSKILLS_WORKDIR=./acme
secskills discover --cidr 203.0.113.0/24 --confirm
secskills enrich    --workdir ./acme --confirm
secskills leakcheck --workdir ./acme --confirm

secskills feed kev
secskills feed epss
secskills feed nvd --product openssh
secskills feed nvd --product nginx
secskills feed nvd --product apache

secskills cvematch     --workdir ./acme
secskills lifecycle reconcile --workdir ./acme
secskills prefix-report --workdir ./acme
```

The report leads with critical exposures and KEV-urgent CVEs, then the
EPSS-ranked long tail. Hand it to the block's admins.

### 2. The CVE the catalogs miss

KEV and EPSS lag real exploitation. EPSS ranking of the *non-KEV* tail is what
surfaces the dangerous unknown. A CVE such as **CVE-2024-6387
(regreSSHion**, OpenSSH RCE, EPSS 0.995) can be widespread yet absent from KEV —
invisible without EPSS weighting. The recipe is just use case 1; the value is in
reading `candidates.jsonl` past the KEV block.

### 3. Open or default-credentialed datastore (owner-authorized)

Only with the asset owner's explicit authorization. Double-gated.

```sh
secskills dbcheck --workdir ./acme --confirm --intrusive-confirm
```

Reports open/default-cred posture for Redis, Elasticsearch, MongoDB, MySQL,
Postgres against a fixed vendor default set (`data/default-credentials.json`) —
not a brute-force wordlist. Records posture, never credential values.

### 4. Headless capture in a VM, process later

No agent, no LLM, air-gapped analysis. See `docs/offline-vm.md`. Short form:

```sh
make bundle                                        # kit = binary + scripts + feeds
# on the VM:
CIDR=203.0.113.0/24 CONFIRM=yes ./capture.sh       # → capture-...tar.gz
# at home, offline:
OUT=./capture-203_0_113_0_24 ./process.sh
```

### 5. Kernel-reachability class (single target, gated)

For the kernel-CVE archetype (reachability, never exploitation — D-4):

```sh
secskills kprobe --ip 203.0.113.9 --port 443 --confirm
```

`mptcp-capable` (native MPTCP dialer) and `ipv4-options-echo` (Record Route via a
socket option, Linux-gated) each send a single non-destructive packet. They
license "a multipath TCP listener is reachable", never "vulnerable".

## How-tos

### Scope a whole ASN safely

```sh
secskills discover --asn AS64500 --confirm
```

This expands to **every announced prefix** — tens of thousands of IPs. Confirm you
mean it; prefer one `--cidr` per run for routine work. Authorization is per IP, and
`out_of_scope` entries in the scope file are never scanned, even under `--confirm`.

### Machine authorization instead of `--confirm` (Mode B)

Issue a signed scope token a worker can verify without a human:

```sh
export SECSKILLS_TOKEN_KEY=…                 # shared HMAC key
secskills token sign   --file scope.json     # → signed token
secskills token verify --file scope.json --ip 203.0.113.9 --class cve
```

The worker refuses any target outside the prefixes, any class outside
`allowed_classes`, any run outside the time window, and **any** intrusive token
regardless of signature (D-4).

### Re-run intelligence against a newer feed, no re-scan

Observations are durable. Next week, refresh the feeds and re-join — no network to
the target:

```sh
secskills feed kev && secskills feed epss
secskills cvematch --workdir ./acme
secskills lifecycle reconcile --workdir ./acme
```

`lifecycle reconcile` diffs the fresh candidate snapshot against stored findings:
a candidate that disappeared (version moved out of range) auto-closes as **fixed
(re-verified)**; one that reappears is flagged **regressed**; human decisions
(`accepted_risk`, `false_positive`) are preserved.

### Triage a finding by hand

```sh
secskills lifecycle set --workdir ./acme \
  --ip 203.0.113.9 --cve CVE-2024-6387 --state accepted_risk --note "mitigated at LB"
```

Legal transitions: `open → confirmed → accepted_risk → fixed → false_positive`
(with re-triage and regression edges). An illegal move is rejected.

### Replay the fixture (no network)

```sh
secskills match
```

Replays `testdata/cve-2026-98432/` (Linux IPv4 TCP use-after-free — not in KEV,
EPSS ~0.005, the archetype proving catalog lag) to three tiers plus a Windows
non-candidate, and renders the §11.3 brief.

## Gotchas

- **`enrich` is target-facing** — it reconnects for banners. Keep it in the capture
  phase, not the offline processing phase.
- **NVD exact-version CVEs** encode the version in the CPE string with no start/end
  bounds (e.g. Apache 2.4.49-only). The parser pins these as exact matches; a naive
  reading treats them as "all versions" and floods candidates.
- **The report is sensitive.** 0600, never published; share only with the asset
  owner's admins.

## Command reference

| Command | Phase | Gate | Output |
|---------|-------|------|--------|
| `plan --asn --shards N` | planning | none (OSINT) | `plan/shard-<i>.txt` |
| `discover --cidr/--asn` | capture | `--confirm` / scope | `observations.jsonl` |
| `enrich` | capture | `--confirm` / scope | `enriched-observations.jsonl` |
| `leakcheck` | capture | `--confirm` | `leaks.jsonl` |
| `dbcheck` | capture | `--confirm --intrusive-confirm` | `dbchecks.jsonl` |
| `kprobe --ip --port` | capture | `--confirm` | `intel.Asset` facts |
| `feed kev/epss/nvd` | feeds | none (OSINT) | `~/.secskills/feed` |
| `cvematch` | process | none | `candidates.jsonl` |
| `lifecycle reconcile/set` | process | none | `findings.jsonl` |
| `prefix-report` | process | none | Markdown report |
| `precision --labels` | gate | none | AC-4 PASS/FAIL (exit 1 on FAIL) |
| `deliver --tenant` | delivery | none | `feed-<tenant>.json` + one-screen brief |
| `notify --tenants` | delivery | none | `notifications.jsonl` + latency PASS/FAIL |
| `fleet --tenants` | intel | none | anonymised cross-tenant ranking |
| `token sign/verify` | — | `SECSKILLS_TOKEN_KEY` | signed token |

### KEV-to-notify latency (NFR-1 / AC-2) and fleet intelligence (FR-9)

When a CVE enters KEV, notify affected tenants in <1h **without a re-scan** — a
pure join of the feed delta journal (`vuln.updated`) against stored candidates:

```sh
secskills feed kev                                   # writes the delta journal
secskills notify --workdir ./acme --tenants tenants.json   # journal-driven
# synthetic AC-2 check:
secskills notify --workdir ./acme --tenants tenants.json \
  --kev-event CVE-2026-98432 --event-at 2026-11-07T12:00:00Z
# VERDICT PASS/FAIL on the 1h budget; FAIL exits 1. No target traffic.
```

Fleet intelligence is an anonymised cross-tenant ranking — counts only, no tenant
id, no asset IP, and a bucket seen in fewer than `k` tenants is suppressed:

```sh
secskills fleet --workdir ./acme --tenants tenants.json --k 2
```

The webhook in `deliver` posts over a **TLS-verifying** client (the feed is
sensitive — scanning's skip-verify is wrong for sending), requires `https`, and
logs only scheme+host (webhook URLs carry secret tokens).

### Launch gate (AC-4) and per-tenant delivery (FR-8/NFR-3)

Before any feed is delivered, measure precision against a committed,
hand-labelled corpus (`testdata/precision/labels.example.jsonl` documents the
schema — `{ip,cve,label}`, label `vuln`|`safe`):

```sh
secskills precision --labels labels.jsonl --workdir ./acme
# VERDICT: PASS/FAIL — FAIL exits 1 (CI gate). Needs >= 100 hosts, precision >= 90%.
```

Deliver a tenant-scoped feed. A tenant is an ASN + its prefixes
(`testdata/tenants.example.json`); `tenantFilter` is the single choke point, so a
feed for one tenant can never carry another's asset (AC-6, covered by a test):

```sh
secskills deliver --workdir ./acme --tenants tenants.json --tenant acme \
  [--webhook https://hooks.example/… ]      # SSRF-guarded POST of the JSON feed
```
