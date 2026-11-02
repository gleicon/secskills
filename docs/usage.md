# Usage & commands

Run `secskills help` for the full list. Every command is one reproducible step.

## Scoping & intake

| Command | Purpose |
|---------|---------|
| `secskills profile <domain>` | Passive OSINT brief (no target traffic) — subdomains, edge/CDN, Shodan IP/ASN/SaaS. Informs the intake. |
| `secskills scope --init` | Write a `.secskills-scope.yml` template. |
| `secskills scope --validate` | Show what the scope file authorizes. |

An authorized, unexpired scope file lets `discover`/`test` pass the gate without
`--confirm`.

## Assessment

| Command | Purpose |
|---------|---------|
| `secskills discover <domain> [--confirm]` | subfinder → dnsx → httpx, Shodan enrichment. Writes `live_hosts.json`. |
| `secskills test <target> [--confirm] [--deep] [--intrusive --intrusive-confirm] [--auth-token/--cookie/--auth-header]` | Headers, TLS, exposure, OSV CVEs. `--deep`: nuclei + sslscan + content discovery + screenshots. |
| `secskills source <path>` | Static ast-grep review (embedded rules). No network, no gate. |
| `secskills sandbox <ctx> --confirm [--port N]` | Docker-isolated build/run, then probe the instance. |
| `secskills graph <seed...> [--output dir]` | Cross-domain exploration graph (OSINT pivots: cert-SAN/CNAME/shared-infra). Discovered domains are NOT tested; each carries an authorization status. |
| `secskills integrity <snapshot\|verify> <url> --confirm [--store file]` | sha256 baseline of a stable endpoint response, re-checked later for drift — AC-1 indicator for a rewriting LLM intermediary. Baselines land in `integrity-baselines.jsonl`. |

Flags work in any position. Live/sandbox refuse without `--confirm` or an
authorized scope file. `--intrusive` requires `--intrusive-confirm`.

## Knowledge & recipes

| Command | Purpose |
|---------|---------|
| `secskills kb` / `secskills kb <class>` | OWASP knowledge base (offline). Classes: injection, access-control, auth-session, crypto-secrets, config-exposure, components-supply-chain, ssrf-xxe, files-deserialization, logging-monitoring, mobile, llm-agents, top10. |
| `secskills recipes` / `secskills recipes <class>` | Per-stack (Node/Python/Go) secure-vs-vulnerable snippets. |

## Findings & reporting

| Command | Purpose |
|---------|---------|
| `secskills findings list\|show <target>` | Inspect the findings store (`~/.secskills-findings/`). |
| `secskills report --render <target>` | Full Markdown report. |
| `secskills report --html <target> --output f.html` | Professional HTML report. |
| `secskills report --pdf <target> --output f.pdf` | Professional PDF (SOC2/ISO/PCI mapped). Needs headless Chrome. |
| `secskills report --retest <target>` | Re-probe the latest run (structured, no shell) → fixed / still-present / regressed; appends a verification note per finding. |
| `secskills tickets <target> [--format csv\|json]` | Export findings as ticket rows (fields = Jira/Linear fields: severity, SLA, priority, asset, owner, business risk). |

## OSINT & data sources

| Command | Purpose |
|---------|---------|
| `secskills shodan <domain\|ip>` | Shodan lookup (software, ports, ASN) — needs `SHODAN_API_KEY` / `shodan init`. |
| `secskills fetch <source> <url>` / `post <source> <url> <json>` | Throttled query of a free source (crtsh/wayback/osv/…) with per-source backoff. |

## Token hygiene

| Command | Purpose |
|---------|---------|
| `secskills compress <file>` | Shrink OSINT output (tldt). |
| `secskills scrub <file>` | Redact PII/secrets before reporting. |
| `secskills scan <file>` | Detect prompt-injection + PII in untrusted target output. |

## Tooling & self-test

| Command | Purpose |
|---------|---------|
| `secskills doctor [--mode --category --tools --json]` | Tool preflight + install commands + build-collision detection. |
| `secskills mcp` | Run as an MCP stdio server. |
| `secskills selftest` | End-to-end pipeline test against a local disposable server. |
