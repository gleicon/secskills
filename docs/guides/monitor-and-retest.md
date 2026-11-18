# Monitoring a target and verifying fixes

After the first assessment: confirm fixes, notice regressions, and keep watching
for drift.

## Verify fixes

```bash
secskills report --retest app.example.com
```

Every finding of the latest run is re-probed with a structured check (no shell)
and marked:

| Result | Meaning |
|---|---|
| FIXED | the condition is gone |
| OPEN | still present |
| REGRESSED | was fixed, is back |
| INCONCLUSIVE | the host could not be reached — never counted as fixed |
| MANUAL | no automatic recheck exists (for example CVE leads); check by hand |

A new run is saved, so the next report shows the change history.

## Watch continuously

```bash
secskills watch app.example.com --confirm --interval 6h
secskills watch app.example.com --confirm --interval 24h --deep
```

Each cycle re-assesses and reports NEW, FIXED, and REGRESSED findings by finding
key. Drift is appended to `watch-drift.jsonl` in the workdir. Run it under a
process supervisor or a scheduled job; `--interval 0` runs once and exits.

## Network blocks

Re-join against fresh intelligence without touching the network, and re-probe
exposed paths:

```bash
secskills feed kev && secskills feed epss
secskills cvematch 203.0.113.0/24
secskills report --retest 203.0.113.0/24
```

Re-run `discover`, `enrich`, and `leakcheck` periodically to refresh what is
listening. See [scan-network-block.md](scan-network-block.md).

## Record decisions so re-runs respect them

```bash
secskills findings set --target app.example.com --id F003 --status accepted --note "compensating WAF rule"
secskills override --target app.example.com --key <finding_key> --severity LOW --reason "…"
```

`accepted` findings stay accepted across re-runs; overrides keep the automated
severity next to the reviewed one.

## Prove a report wasn't changed

```bash
secskills attest --sign   app.example.com
secskills attest --verify app.example.com
```

The run metadata and evidence chain are signed with your ed25519 key
(`~/.secskills-keys/`); any later change fails verification.
