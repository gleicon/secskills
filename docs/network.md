# Network mode — scanning a block you own

Network mode assesses an ASN or CIDR you are authorized to test. It sweeps the
block, records every reachable service, checks for exposures, and matches
service versions against known CVEs. Results are **ordinary findings**: the same
`report`, `report --retest`, `tickets`, `export`, `override`, and `attest` you use
for an app assessment work on a block. Design and decisions: `SPEC-NETWORK.md`.

## The flow

```
discover --cidr/--asn ─▶ observations.jsonl            reachable ip:port (gated)
enrich                ─▶ enriched-observations.jsonl   product / version / CPE (gated)
leakcheck             ─▶ findings                       exposed .git/.env/server-status,
                                                        open Redis/Elasticsearch (gated)
dbcheck               ─▶ findings                       vendor default credentials (double-gated)
feed kev|epss|nvd     ─▶ ~/.secskills/feed             intelligence cache (no target traffic)
cvematch              ─▶ findings + candidates.jsonl   CVE leads per service (offline)
report / tickets / export / retest                     the usual tools, on the block
```

Every command takes the block as written to `discover` (`203.0.113.0/24` or
`AS64500`). That name selects the workdir and the findings store. `leakcheck`,
`dbcheck`, and `cvematch` save a run each time, so `report --retest` and `watch`
have something to compare against.

## End to end

You are authorized to assess `203.0.113.0/24`:

```sh
secskills discover --cidr 203.0.113.0/24 --confirm
secskills enrich    203.0.113.0/24 --confirm
secskills leakcheck 203.0.113.0/24 --confirm

secskills feed kev
secskills feed epss
secskills feed nvd --product openssh
secskills feed nvd --product nginx

secskills cvematch 203.0.113.0/24
secskills report --pdf 203.0.113.0/24 --output block.pdf
secskills tickets 203.0.113.0/24 --format csv --output block.csv
```

The report contains the findings and a network inventory (hosts, services,
datastores reachable from the internet).

## What becomes a finding

| Observed | Finding | Severity |
|---|---|---|
| `.git`, `.env`, `server-status`, directory listing served | `Exposed path: …` | MEDIUM; potential HIGH when an `.env` exposes credential-like keys |
| Redis or Elasticsearch answering without authentication | `Unauthenticated …` | HIGH |
| A datastore accepting a vendor default credential (`dbcheck`) | `… accepts a vendor default credential` | HIGH |
| A banner version inside NVD CVE ranges | `Potentially vulnerable <product> version <v> …`, listing the CVEs | LOW; MEDIUM when one of them is in CISA KEV |

CVE matches are **leads to validate**: a distribution can fix a CVE without
changing the version in the banner. Credential values are never recorded, only
key names and the fact of exposure.

## Next week: what changed?

Observations stay in the workdir. Refresh the intelligence and re-join, with no
traffic to the block:

```sh
secskills feed kev && secskills feed epss
secskills cvematch 203.0.113.0/24
```

A lead that no longer matches (the service was upgraded or is gone) closes as
fixed; one that comes back reopens as regressed. To re-check the network itself,
re-run `discover`, `enrich`, and `leakcheck` first.

Exposed-path findings can also be re-probed directly:

```sh
secskills report --retest 203.0.113.0/24
```

## Triage

Mark a finding as an accepted risk, or change its severity with a reason. Re-runs
keep your decision:

```sh
secskills findings show 203.0.113.0/24                     # IDs look like NET-CVE-203.0.113.10:22
secskills findings set --target 203.0.113.0/24 --id NET-CVE-203.0.113.10:22 \
  --status accepted --note "fixed via distro backport, verified on host"
secskills override --target 203.0.113.0/24 --key <finding_key> --severity LOW \
  --reason "fixed via distro backport, verified on host"
```

## Datastore default credentials (owner-authorized only)

```sh
secskills dbcheck 203.0.113.0/24 --confirm --intrusive-confirm
```

Tries a short fixed list of vendor defaults (`data/default-credentials.json`) for
Redis, Elasticsearch, and MySQL, and checks MongoDB for unauthenticated access.
It is not a brute-force wordlist and reads no data beyond one liveness command.

## Large blocks

A whole ASN can be tens of thousands of addresses:

```sh
secskills discover --asn AS64500 --confirm     # every announced prefix
```

Blocks wider than /20 need `--allow-large`. Authorization is checked per IP, and
`out_of_scope` entries in the scope file are never scanned. To split the work
across machines:

```sh
secskills plan --asn AS64500 --shards 4 --out ./plan    # one prefix list per worker
```

## Capture on a machine near the block, analyze elsewhere

See [offline-vm.md](offline-vm.md). Short form:

```sh
make bundle                                           # binary + scripts + feed cache
CIDR=203.0.113.0/24 CONFIRM=yes ./capture.sh          # on the capture machine
OUT=./capture-203_0_113_0_24 BLOCK=203.0.113.0/24 ./process.sh   # at home, offline
```

## Commands

| Command | Touches the block | Gate | Produces |
|---|---|---|---|
| `discover --cidr/--asn` | yes | `--confirm` or scope | `observations.jsonl` |
| `enrich <block>` | yes | `--confirm` or scope | `enriched-observations.jsonl` |
| `leakcheck <block>` | yes | `--confirm` or scope | findings, `leaks.jsonl` |
| `dbcheck <block>` | yes | `--confirm --intrusive-confirm` | findings, `dbcheck.jsonl` |
| `feed kev\|epss\|nvd` | no | — | feed cache |
| `cvematch <block>` | no | — | findings, `candidates.jsonl` |
| `plan --asn` | no (RIPE/IRR only) | — | `plan.json`, `shard-<i>.txt` |
