# Exploring a target's attack surface

How to find and dig into the kinds of resources a target exposes: subdomains,
identity providers, APIs, registries, monitoring, object storage, DNS, and the
CDN in front of it all. Most of this happens inside `discover` and `test`; this
guide shows where each result comes from and how to go further.

## Before you start

Authorization and a scope file, as in [pentest-web-app.md](pentest-web-app.md).
Optional keys widen what you see: `SHODAN_API_KEY`, `CENSYS_API_ID` +
`CENSYS_API_SECRET`. They are read from the environment and never written into reports.

## Subdomains, DNS, and related domains

```bash
secskills profile example.com          # passive: subdomains, env tiers, CDN, mail/NS providers
secskills discover example.com         # resolve and probe live HTTP services
secskills graph example.com --output graph/   # related domains via certificate SANs, CNAMEs, shared infrastructure
```

`graph` writes `graph.json` and `graph.md`. Every related domain carries an
authorization status and is **never tested** — use it to ask the owner what
belongs in scope. `test` adds DNS hygiene per apex: missing or permissive SPF,
missing DMARC or `p=none`, wildcard DNS, and dangling CNAMEs that point at
unclaimed cloud resources (subdomain-takeover candidates).

Query free sources directly through the throttled wrapper:

```bash
secskills fetch crtsh "https://crt.sh/?q=%25.example.com&output=json"
secskills fetch wayback "http://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=text&fl=original&collapse=urlkey"
secskills shodan example.com           # software, ports, ASN (needs a key)
```

## Technologies, panels, and internal services

`test` fingerprints each live host from headers, cookies, body, and favicon
hash. A recognized service triggers a second-stage, read-only check:

| Fingerprint | Second-stage check |
|---|---|
| MinIO, S3-compatible storage | anonymous bucket listing |
| Elasticsearch, Kibana | cluster and index exposure |
| Grafana | anonymous org/API access |
| Vault, Consul | seal status, unauthenticated API |
| Argo CD, Harbor, Kubernetes, GitLab, Jenkins | unauthenticated catalog/API exposure |

Findings appear as `Operational service exposed: <name>` and pivot findings. The
fingerprint registry grows with you:

```bash
secskills fp list
secskills fp add --name "Internal Portal" --category admin --header "X-Portal:1"
secskills fp import technologies.json                               # Wappalyzer-format data
```

## APIs and identity

`test` looks for OpenAPI/Swagger documents, GraphQL endpoints with introspection
enabled, and OAuth/OIDC discovery documents, and reports them with what they
expose. With `--profile adversarial-readonly`, discovered surfaces feed the
runtime planner: an OIDC provider leads to JWKS retrieval and auth-flow checks; a
disclosed internal hostname is resolved externally to see whether it is public.

With test accounts, the logged-in API surface is in reach:

```bash
secskills test example.com --auth-token "$A" --auth-token-b "$B"   # JWT checks, cookie flags, BOLA/IDOR differential
```

## Object storage

Bucket names are guessed from the domain and discovered labels (for
`assets.example.com`: `assets`, `example-assets`, …) and checked for anonymous
listing on S3 and Google Cloud Storage. A public bucket is a finding; a private
`403` is not.

## Monitoring and debug endpoints

Exposure checks cover `/metrics`, health and debug endpoints, `.git`, `.env`, and
similar paths, compared against a random path so a catch-all `200` is not a
finding. `/metrics` output is inspected: internal hostnames or Kubernetes names
raise the severity; a credential-like pattern is flagged as unvalidated.

## The CDN, the WAF, and the origin

`test` records the edge (CDN, WAF, `Via`) and the favicon hash. With
`--profile adversarial-readonly` and a Shodan or Censys key, it searches for IPs
presenting the same favicon or certificate and checks whether the origin answers
directly — matching the leaf certificate to confirm it is the same service — and
whether trusted headers bypass access controls at the edge.

## Where the results go

Everything lands as findings in the target's workdir and in a saved run:

```bash
secskills report --render example.com     # includes the edge map, attack graph, and planner decisions
secskills findings show example.com
```

## Going deeper

- `thirdparty/redteam-pentest.md` Phases 1–2 for manual reconnaissance technique.
- `secskills kb config-exposure` and `secskills kb access-control` for what to
  check next and how to fix what you find.
