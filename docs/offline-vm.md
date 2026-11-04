# Running headless in a VM — capture now, process later

Exposure mode is built so the expensive, network-facing work (sweeping a block,
grabbing banners, probing exposure) happens in one place and the analysis
(joining against vulnerability feeds, scoring, reporting) happens anywhere, even
air-gapped. This is a direct consequence of the design: the center of gravity is
the **Observation**, a timestamped, content-addressed, append-only record, not a
live finding. Everything downstream is a deterministic join over stored
observations.

Two properties make the split clean:

- **No LLM, no agent in v0.** The whole external pipeline is plain Go. The only
  LLM consumers are the future Phase-2 L3 agent tier (which may assert patch
  state) and the `llmproxy` probe — and that probe *tests* an LLM API router as
  a target, it is not a runtime dependency. You can run everything described here
  with no model and no network beyond the targets.
- **No CGO.** `make dist` cross-compiles a single static binary per platform.
  Copy it to a VM; it needs no runtime, no shared libraries, no interpreter.

## The three phases and what each one needs

| Phase | Commands | Network reach |
|-------|----------|---------------|
| **Capture** (target-facing) | `discover --cidr/--asn`, `enrich`, `leakcheck`, `dbcheck`, `kprobe` | the targets; RIPE Stat / `whois` when resolving an ASN |
| **Feeds** (OSINT, not the target) | `feed kev`, `feed epss`, `feed nvd --product <p>` | the internet (CISA, FIRST, NVD) only |
| **Process** (offline joins) | `cvematch`, `lifecycle reconcile`, `prefix-report` | none — local JSONL only |

`enrich` belongs in **capture**, not process: it reconnects to each host to read
service banners. Everything in **process** reads only files.

The feed stage is independent of the target. Run it on the VM (`ONLINE=yes`) to
make the workdir self-contained, or fetch it once anywhere and ship the cache
directory with the kit. The cache lives at `~/.secskills/feed`, overridable with
`SECSKILLS_FEED`.

## The portable artifact: the workdir

Everything a capture produces is one directory, pinned with `SECSKILLS_WORKDIR`:

```
capture-203_0_113_0_24/
  observations.jsonl           # the substrate: every reachable service, raw
  enriched-observations.jsonl  # + product/version/CPE from banners
  leaks.jsonl                  # exposed .git/.env, dir listings, unauth stores
  dbchecks.jsonl               # datastore auth posture (if INTRUSIVE=yes)
  data/                        # ASN→prefix resolution cache
```

After `process.sh` it also holds `candidates.jsonl`, `findings.jsonl`, and the
Markdown report. The workdir is append-only and resumable: a kill mid-sweep
keeps every observation already written (AC-7), so a capture can be stopped and
restarted on a flaky VM without losing or corrupting data.

## Build and package

```sh
make dist      # dist/secskills-{linux-amd64,linux-arm64,darwin-arm64}
make bundle    # dist/secskills-kit.tar.gz = binary + scripts + feed cache
```

`make bundle` folds in your local `~/.secskills/feed` cache if present, so the
kit processes fully offline. Run `secskills feed kev` once before bundling to
seed it.

## End to end

On the VM (authorize with a scope file or `CONFIRM=yes`):

```sh
CIDR=203.0.113.0/24 CONFIRM=yes ONLINE=yes ./capture.sh
# → capture-203_0_113_0_24.tar.gz
```

Carry the tarball home, then offline:

```sh
tar -xzf capture-203_0_113_0_24.tar.gz
OUT=./capture-203_0_113_0_24 ./process.sh
```

## Notes

- **Authorization is still enforced headless.** `discover` refuses a block
  without an authorized, unexpired scope file or `--confirm`; authorization is
  decided per IP, and `out_of_scope` entries are never scanned even under
  `--confirm`. A whole-ASN sweep (`ASN=AS...`) expands to every announced prefix
  — deliberate and large; prefer a `CIDR=` per run.
- **`dbcheck` is double-gated.** `INTRUSIVE=yes` passes both `--confirm` and
  `--intrusive-confirm`. Use it only with the asset owner's explicit
  authorization. It tests a fixed vendor default-credential set, never a
  brute-force wordlist, and records no credential values.
- **Optional external tools** (`whois`, `mysql`) are only needed for the ASN IRR
  fallback and the MySQL datastore check respectively. The core sweep and report
  need nothing but the static binary.
- **The report is sensitive.** It is written 0600 and never published. Share it
  only with the asset owner's administrators.
