# Usage & commands

Run `secskills help` for the list and `secskills <command> -h` for flags. Every
command is one reproducible step. The same reference, formatted, is on the
[website](https://gleicon.github.io/secskills/usage.html).

## Concepts

- **Authorization gate.** Commands that send traffic to a target refuse to run until
  you pass `--confirm` or keep an authorized, unexpired scope file listing the target.
- **Scope file.** `.secskills-scope.yml` (or `$SECSKILLS_SCOPE`): engagement, who
  confirmed it, `targets`, `out_of_scope`, `expires`, `intrusive`. It counts only when
  owned by you and not group/other-writable. A listed domain covers its subdomains; a
  listed CIDR covers its addresses.
- **Workdir.** Per-target scratch space for discovery output and evidence:
  `$SECSKILLS_WORKDIR`, else `<user cache dir>/secskills/<target>` (`~/.cache` on
  Linux, `~/Library/Caches` on macOS). Created `0700`; a symlinked or foreign-owned
  workdir is refused.
- **Findings store.** Saved runs in `~/.secskills-findings/<target>/`. Reports, tickets,
  exports, and retests read from it. Treat it like a credentials store.

### Test profiles (`test --profile`)

| Profile | Adds |
|---------|------|
| `passive` | OSINT only, no target traffic beyond discovery. |
| `safe-active` (default) | Header, TLS, and exposure checks. |
| `adversarial-readonly` | Bypass variants, safe exploit primitives, OAST callbacks, stateful pivots. Still read-only. |
| `authorized-exploit` | Credentialed and state-changing tests. Needs `--intrusive --intrusive-confirm`. |

## Scoping & intake

| Command | Purpose |
|---------|---------|
| `secskills profile <domain>` | Passive OSINT brief (no target traffic) — subdomains, edge/CDN, Shodan IP/ASN/SaaS. Informs the intake. |
| `secskills scope --init` | Write a `.secskills-scope.yml` template. |
| `secskills scope --validate` | Show what the scope file authorizes. |

## Assessment

| Command | Purpose |
|---------|---------|
| `secskills discover <domain> [--confirm]` | subfinder → dnsx → httpx, Shodan enrichment. Writes `live_hosts.json` to the workdir. |
| `secskills test <target> [--confirm] [--deep] [--profile P]` | Headers, TLS, exposure, OSV CVEs, technology packs. `--deep`: nuclei + sslscan + content discovery + screenshots. |
| `secskills source [--json] <path>` | Static ast-grep review (embedded rules). No network, no gate. |
| `secskills sandbox <ctx> --confirm [--port N]` | Docker-isolated build/run, then probe only that container. Refuses without Docker. |
| `secskills graph <seed...> [--output dir]` | Cross-domain exploration graph (cert-SAN/CNAME/shared-infra). Discovered domains are NOT tested; each carries an authorization status. |
| `secskills watch <target> --confirm [--interval 6h]` | Re-assess on a schedule; report NEW / FIXED / REGRESSED by finding key. |
| `secskills integrity <snapshot\|verify> <url> --confirm [--store file]` | sha256 baseline of a stable response, re-checked later for drift (rewriting-intermediary indicator). |

### `test` flags worth knowing

| Flag | Use |
|------|-----|
| `--auth-token`, `--cookie`, `--auth-header` | Test the authenticated surface. Omitted: authenticated checks are reported *not available*. |
| `--auth-token-b`, `--cookie-b` | Second identity for the BOLA/IDOR differential. |
| `--insecure-auth` | Send credentials to a host with an untrusted certificate. Off by default. |
| `--intrusive` + `--intrusive-confirm` | Allow write/credential tests. Both required. |

Flags work in any position for `discover`, `test`, `sandbox`, `profile`, `graph`,
`watch`, `integrity`, `tickets`, and `export`. Other commands take flags before positional
arguments (`secskills source --json ./repo`).

## Findings & reporting

| Command | Purpose |
|---------|---------|
| `secskills findings list\|show <target>` | Inspect the findings store. |
| `secskills report --render <target>` | Full Markdown report. |
| `secskills report --html <target> --output f.html` | Professional HTML report. |
| `secskills report --pdf <target> --output f.pdf` | Professional PDF (SOC2/ISO/PCI mapped). Needs headless Chrome. |
| `secskills report --audit <target>` | Concise auditor report: control objectives, ledger, attestation. |
| `secskills report --lint <target>` | Check report invariants before sending. |
| `secskills report --retest <target>` | Re-probe the latest run (structured, no shell) → fixed / still-present / regressed. |
| `secskills tickets <target> [--format csv\|json]` | Ticket rows (severity, SLA, priority, asset, owner, business risk). |
| `secskills export --format sarif\|cyclonedx <target>` | SARIF 2.1.0, or CycloneDX 1.5 + VEX. |
| `secskills override --target T --key K --severity S --reason R` | Auditable severity adjudication; the automated value is kept. |
| `secskills attest --sign\|--verify <target>` | ed25519-sign a run, or verify it (key in `~/.secskills-keys/`). |

## Exposure mode (ASN / CIDR)

Capture stages touch the network and are gated; the rest are offline joins over the
workdir. Recipes: [exposure.md](exposure.md). Headless capture: [offline-vm.md](offline-vm.md).

| Command | Purpose |
|---------|---------|
| `secskills discover --cidr C \| --asn A [--allow-large] --confirm` | Sweep a block into `observations.jsonl`. Per-IP authorization; > /20 needs `--allow-large`. |
| `secskills enrich --workdir D --confirm` | Banner → product/version/CPE. |
| `secskills leakcheck --workdir D --confirm` | Exposed .git/.env, listings, server-status, unauthenticated datastores. Values redacted. |
| `secskills dbcheck --workdir D --confirm --intrusive-confirm` | Open/default-credential datastore posture (fixed vendor set, never brute force). |
| `secskills kprobe --ip I --port P --confirm` | Single-packet MPTCP / IPv4-options reachability (Linux for IPv4 options). |
| `secskills feed kev\|epss\|nvd --product P` | Cache CISA KEV, FIRST EPSS, NVD ranges (`~/.secskills/feed` or `$SECSKILLS_FEED`). |
| `secskills cvematch --workdir D` | Version-inferred CVE candidates, KEV first then EPSS. |
| `secskills lifecycle reconcile\|set --workdir D` | Finding states: open, confirmed, accepted_risk, fixed, false_positive. |
| `secskills prefix-report --workdir D [--label L]` | Markdown exposure report for the block. |
| `secskills plan --asn A --shards N --out dir` | Split an ASN's prefixes across N capture workers. |
| `secskills token sign\|verify --file F` | HMAC scope tokens for unattended workers (`SECSKILLS_TOKEN_KEY`). |
| `secskills precision --labels L --workdir D` | Precision gate against a labelled set. |
| `secskills deliver --tenants F --tenant T --workdir D [--webhook https://…]` | One tenant's feed. |
| `secskills notify --tenants F --workdir D` | Event → notification latency check. |
| `secskills fleet --tenants F --workdir D [--k N]` | Anonymised cross-tenant ranking. |
| `secskills match [--fixture dir] [--json]` | Replay the deterministic matcher on a fixture. |

## Knowledge & recipes

| Command | Purpose |
|---------|---------|
| `secskills kb` / `secskills kb <class>` | OWASP knowledge base (offline). Classes: injection, access-control, auth-session, crypto-secrets, config-exposure, components-supply-chain, ssrf-xxe, files-deserialization, logging-monitoring, mobile, llm-agents, top10. |
| `secskills recipes` / `secskills recipes <class>` | Per-stack (Node/Python/Go) secure-vs-vulnerable snippets. |

## OSINT & data sources

| Command | Purpose |
|---------|---------|
| `secskills shodan <domain\|ip>` | Shodan lookup (software, ports, ASN) — needs `SHODAN_API_KEY` / `shodan init`. |
| `secskills fetch <source> <url>` / `post <source> <url> <json>` | Throttled query of a free source (crtsh/wayback/osv/…) with per-source backoff. |
| `secskills fp list\|add\|import` | Technology fingerprint registry (imports Wappalyzer data). |

## Token hygiene

| Command | Purpose |
|---------|---------|
| `secskills compress <file>` | Shrink OSINT output (tldt). |
| `secskills scrub <file>` | Redact PII/secrets before reporting. |
| `secskills scan <file>` | Detect prompt-injection + PII in untrusted target output. |

## Tooling & self-test

| Command | Purpose |
|---------|---------|
| `secskills doctor [--mode --category --tools --quiet --json --list-categories]` | Tool preflight + install commands + name-collision detection. |
| `secskills mcp` | Read-only MCP stdio server (`doctor`, `kb_list`, `kb_get`, `recipes_get`, `source_scan`, `fetch`). |
| `secskills oast-server` | Self-hosted OAST callback listener for blind SSRF validation. |
| `secskills conformance` / `measure` / `selftest` | Detector scorecard, local-corpus precision/recall, end-to-end pipeline test. |

## Files & environment

| Name | Meaning |
|------|---------|
| `SECSKILLS_WORKDIR` | Workdir instead of the per-user default. Keep it private; never `/tmp`. |
| `SECSKILLS_SCOPE` | Scope file path instead of `./.secskills-scope.yml`. |
| `SECSKILLS_FEED` | Feed cache instead of `~/.secskills/feed`. |
| `SECSKILLS_RATE` | Requests per second for sweeps and probes (default 5). |
| `SECSKILLS_TOKEN_KEY` | Shared HMAC key for scope tokens. |
| `SECSKILLS_OAST_DOMAIN`, `SECSKILLS_OAST_POLL_URL` | Your OAST collaborator. |
| `SHODAN_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET` | Optional OSINT keys; never written into reports. |
| `~/.secskills-findings/` | Findings store. |
| `~/.secskills-keys/` | Attestation signing key (created on first use). |
| `~/.secskills-fingerprints.json` | Your fingerprint registry additions. |
