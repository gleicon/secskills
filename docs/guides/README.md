# Guides

Task-by-task walkthroughs. Each one says what to have ready, the commands in
order, how to read the results, and where to go deeper. Every command that
touches a target assumes you hold **written authorization** for it.

| You want to… | Guide |
|---|---|
| Run a full penetration test of a web app or domain | [pentest-web-app.md](pentest-web-app.md) |
| Map and dig into what a target exposes: identity, registries, storage, APIs, DNS, CDN | [explore-attack-surface.md](explore-attack-surface.md) |
| Sweep an ASN or CIDR you own for exposures and CVE leads | [scan-network-block.md](scan-network-block.md) |
| Run a large sweep from machines near the network and analyze it elsewhere | [capture-offline.md](capture-offline.md) |
| Review source code, locally or in CI | [review-source.md](review-source.md) |
| Test a build without touching production | [test-in-sandbox.md](test-in-sandbox.md) |
| Test an LLM app, chatbot, or LLM API gateway | [test-llm-apps.md](test-llm-apps.md) |
| Keep watching a target and verify fixes | [monitor-and-retest.md](monitor-and-retest.md) |

## Resources and the commands that cover them

| Resource | Found by | Tested by |
|---|---|---|
| Subdomains, DNS, mail policy | `profile`, `discover` | `test` (DNS hygiene, dangling CNAME) |
| Web apps and APIs | `discover` | `test`, `test --deep` |
| OpenAPI / GraphQL schemas, OIDC providers | `test` (detector packs) | `test --profile adversarial-readonly` |
| Registries, CI/CD, monitoring, secrets managers | `test` (fingerprints) | second-stage packs in `test` |
| Object storage buckets | `test` | `test` (anonymous list/read) |
| CDN / WAF and the origin behind it | `test` (edge recon) | `test --profile adversarial-readonly` (origin bypass) |
| Related domains (certificates, CNAMEs, shared infrastructure) | `graph` | not tested — listed for scope review |
| Network blocks: every reachable service | `discover --cidr/--asn` | `enrich`, `leakcheck`, `dbcheck`, `cvematch` |
| Source code | — | `source` |
| A container image or buildable artifact | — | `sandbox` |
| LLM chat endpoints | `test` | `test`, `test --profile adversarial-readonly`, `integrity` |

Reference material: [usage](../usage.md) (every command and flag),
[reporting](../reporting.md), [architecture](../architecture.md).
