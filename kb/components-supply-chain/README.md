---
class: components-supply-chain
owasp_top10: A06:2021 — Vulnerable and Outdated Components
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Vulnerable Dependency Management, url: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html}
  - {name: NPM Security best practices, url: https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html}
  - {name: Third Party JavaScript Management, url: https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html}
  - {name: Software Supply Chain Security, url: https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html}
---

# Vulnerable & Outdated Components (A06)

## Detection
- Version strings: `Server:`/`X-Powered-By` headers, `/version` endpoints, JS bundle names, Prometheus `*_version_info` metrics, httpx `-td`.
- Lockfiles in source/images (`package-lock.json`, `requirements.txt`, `go.sum`, `Cargo.lock`, `pom.xml`, `Gemfile.lock`).
- Query **OSV**: `osv-scanner --recursive`/`--docker` for lockfiles+OS packages; `curl api.osv.dev/v1/query` for bare version strings with no lockfile. Use the union; query both PyPI and Debian for server components (backported patches differ).

Severity by CVE count (any severity): 1–5 MEDIUM · 6–20 HIGH · >20 HIGH (escalate to CRITICAL if any CVSS ≥ 9.0 present).

## Remediation
- Maintain an inventory/**SBOM**; know every direct and transitive dependency and version.
- Automated dependency scanning in CI (OSV/Dependabot/Snyk); fail the build on known-exploitable CVEs.
- Patch/upgrade on a schedule; remove unused dependencies.
- Pin versions with lockfiles; verify integrity hashes.
- npm: avoid install scripts from untrusted packages, use `npm ci`, audit, scope internal packages.
- Third-party JS: minimize, self-host where feasible, add **SRI**, isolate with CSP.

## Verify the fix
Re-query OSV for the upgraded version — expect zero applicable CVEs; confirm the
version string in headers/metrics reflects the patched release.
