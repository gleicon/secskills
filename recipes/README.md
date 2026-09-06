# Recipes — secure-vs-vulnerable, per stack

Concrete Node.js / Python / Go snippets that turn `kb/` guidance into code.
Each recipe pairs with its KB class (remediation rationale) and, for source
mode, the ast-grep rule that detects the vulnerable form.

| Recipe | OWASP | KB class | ast-grep rule prefixes |
|--------|-------|----------|------------------------|
| [injection.md](injection.md) | A03 | `kb/injection/` | `*-injection-*`, `*-xss-*`, `*-sql-*` |
| [access-control.md](access-control.md) | A01 | `kb/access-control/` | `*-missing-auth*`, `vibe-*-skip-*-auth` |
| [auth-session.md](auth-session.md) | A07 | `kb/auth-session/` | `*-jwt-*-secret`, `*-secret-hardcoded*` |
| [crypto-secrets.md](crypto-secrets.md) | A02 | `kb/crypto-secrets/` | `*-rand-not-crypto`, `*-secret-*`, `*-tls-*` |
| [config-exposure.md](config-exposure.md) | A05/A08 | `kb/config-exposure/` | `*-cors-wildcard`, `*-debug-*`, `*-display-errors*` |
| [ssrf-xxe.md](ssrf-xxe.md) | A10 | `kb/ssrf-xxe/` | `*-ssrf-*`, `*-yaml-load-unsafe` |

Classes without a dedicated recipe file — remediation lives in the KB:
- **files-deserialization** (A08): `kb/files-deserialization/` — file upload, path traversal, deserialization (`*-pickle-loads`, `*-marshal-load`, `*-yaml-load-unsafe`).
- **components-supply-chain** (A06): `kb/components-supply-chain/` — dependency upgrades are version bumps, not code snippets.
- **logging-monitoring** (A09): `kb/logging-monitoring/` — log the right events, never log secrets (`*-console-log-credential`).

Convention in each file: a `// VULN:` line shows the insecure form, the line
below shows the fix. The VULN lines are teaching examples, not live code.
