# secskills capture kit

A self-contained, headless capture kit: one static binary, two scripts, and
(optionally) a vulnerability-feed cache. No agent, no LLM, no interpreter. Drop
it on a VM near the target network, capture, carry the workdir home, process it
offline.

## Contents

| File | Role |
|------|------|
| `secskills` | static linux/amd64 binary (CGO off) |
| `capture.sh` | target-facing sweep → portable workdir of JSONL |
| `process.sh` | offline join of the workdir against the feeds → report |
| `feed/` | optional pre-fetched KEV/EPSS/NVD cache (ship it to stay air-gapped) |

## On the VM

```sh
# authorize via a scope file, or assert CONFIRM=yes
CIDR=203.0.113.0/24 CONFIRM=yes ./capture.sh
# → capture-203_0_113_0_24.tar.gz
```

Add `INTRUSIVE=yes` only with the asset owner's authorization (runs the
default-credential datastore posture check). Add `ONLINE=yes` to fetch the KEV
and EPSS feeds on the VM so the workdir needs nothing later.

## At home (offline)

```sh
tar -xzf capture-203_0_113_0_24.tar.gz
OUT=./capture-203_0_113_0_24 ./process.sh      # uses the shipped feed/ cache
# → candidates.jsonl, findings.jsonl, prefix report (Markdown)
```

The report contains no credential values (key names only). It is sensitive
engagement data: 0600, local, share only with the asset owner's admins.

See `docs/offline-vm.md` for the full packaging rationale and the online/offline
feed split.
