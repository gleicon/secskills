---
class: top10
title: OWASP Top 10 2021 — index
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Top 10 (https://owasp.org/www-project-top-ten/) + OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
---

# OWASP Top 10 2021 → secskills class → cheat sheets

Each category maps to a KB class directory and the cheat sheets bundled there.
Test skills use this matrix to pull the right remediation text per finding.

| # | Category | KB class | Primary cheat sheets |
|---|----------|----------|----------------------|
| A01 | Broken Access Control | `kb/access-control/` | Authorization, IDOR Prevention, CSRF Prevention, Access Control |
| A02 | Cryptographic Failures | `kb/crypto-secrets/` | Cryptographic Storage, TLS, Password Storage, Secrets Management, Key Management |
| A03 | Injection | `kb/injection/` | XSS Prevention, DOM XSS, SQL Injection Prevention, Query Parameterization, OS Command Injection, LDAP Injection |
| A04 | Insecure Design | `kb/access-control/` + `kb/auth-session/` | Threat Modeling, Abuse Case, Forgot Password |
| A05 | Security Misconfiguration | `kb/config-exposure/` | Security Headers, CSP, CORS, Clickjacking Defense, Error Handling |
| A06 | Vulnerable & Outdated Components | `kb/components-supply-chain/` | Vulnerable Dependency Mgmt, NPM Security, Third-Party JS, SRI |
| A07 | Identification & Authentication Failures | `kb/auth-session/` | Authentication, Password Storage, Session Management, JWT, MFA, Credential Stuffing |
| A08 | Software & Data Integrity Failures | `kb/config-exposure/` + `kb/files-deserialization/` | SRI, Deserialization, Supply Chain |
| A09 | Security Logging & Monitoring Failures | `kb/logging-monitoring/` | Logging, Application Logging Vocabulary |
| A10 | Server-Side Request Forgery (SSRF) | `kb/ssrf-xxe/` | SSRF Prevention, XXE Prevention |

## Companion frameworks (beyond Web)

secskills maps findings across three OWASP Top 10 families — pick by target type:

| Framework | Target | KB class |
|-----------|--------|----------|
| OWASP Top 10 2021 (Web) | web apps / APIs | `kb/*` (the table above) |
| OWASP Mobile Top 10 2024 (+ MASVS/MASTG) | Android/iOS apps + backends | `kb/mobile/` |
| OWASP Top 10 for LLM Apps 2025 (+ Agentic) | LLM/RAG/agent systems | `kb/llm-agents/` |

Mobile backends and LLM tool-endpoints are also web APIs — cross-apply the Web
Top 10 (`kb/access-control`, `kb/auth-session`, `kb/injection`, `kb/ssrf-xxe`).

## Coverage matrix template (for reports)

| Control | ID | Finding | Status | Severity |
|---------|-----|---------|--------|---------|
| Broken Access Control | A01 | FINDING-NN / — | Fail/Pass/Partial/Not Tested | — |
| Cryptographic Failures | A02 | | | |
| Injection | A03 | | | |
| Insecure Design | A04 | | | |
| Security Misconfiguration | A05 | | | |
| Vulnerable & Outdated Components | A06 | | | |
| Identification & Auth Failures | A07 | | | |
| Software & Data Integrity | A08 | | | |
| Logging & Monitoring Failures | A09 | | | |
| SSRF | A10 | | | |

Source: OWASP Top 10 2021 — https://owasp.org/Top10/
