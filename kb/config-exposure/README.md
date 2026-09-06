---
class: config-exposure
owasp_top10: A05:2021 — Security Misconfiguration (+ A08 Integrity)
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: HTTP Security Response Headers, url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html}
  - {name: Content Security Policy, url: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html}
  - {name: Cross-Origin Resource Sharing (CORS), url: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html}
  - {name: Clickjacking Defense, url: https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html}
  - {name: Error Handling, url: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html}
  - {name: REST Security, url: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html}
---

# Security Misconfiguration & Exposure (A05 / A08)

## Detection
- Missing security headers (HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy).
- `Access-Control-Allow-Origin: *` on authenticated endpoints; reflected `Origin`.
- Exposed `/metrics`, health/status, admin consoles, dir listing, default creds.
- Exposed infra: container registry, Keycloak admin, Grafana datasources, Elasticsearch indices, Jaeger traces, S3 buckets, GraphQL introspection.
- Verbose errors / stack traces; missing SRI on third-party scripts (A08).

## Security headers — remediation
| Header | Set to |
|--------|--------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | restrictive; no wildcard `script-src`/`connect-src`; nonce/hash for inline |
| `X-Frame-Options` / CSP `frame-ancestors` | `DENY`/`SAMEORIGIN` (clickjacking) |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | deny unused features |

## CSP
- Avoid `unsafe-inline`/`unsafe-eval`; use nonces or hashes. Set `object-src 'none'`, `base-uri 'none'`, `frame-ancestors`.
- Note: CSP `connect-src` may disclose internal domains — add them to scope-expansion candidates, don't auto-probe.

## CORS
- Never reflect arbitrary `Origin` with `Allow-Credentials: true`. Allow-list exact origins.
- `Access-Control-Allow-Origin: *` must never combine with credentials or sensitive data.

## Exposure hardening
- Authenticate/firewall `/metrics`, admin consoles, monitoring UIs, registries; never internet-facing without auth.
- Disable dir listing, default accounts, sample apps, verbose banners.
- S3/GCS: block public list/read/write unless required; no wildcard bucket CORS.

## Error handling & integrity
- Generic error pages; log details server-side only.
- SRI (`integrity=`) on all CDN scripts; pin/lock third-party JS (A08).

## Verify the fix
Re-request headers (present + correct), confirm CORS rejects a foreign origin,
and confirm the exposed endpoint now requires auth or is unreachable.
