---
class: crypto-secrets
owasp_top10: A02:2021 — Cryptographic Failures
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Cryptographic Storage, url: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html}
  - {name: Transport Layer Security, url: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html}
  - {name: Secrets Management, url: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html}
  - {name: Key Management, url: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html}
  - {name: HTTP Strict Transport Security, url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html}
---

# Cryptographic Failures (A02)

## Detection
- TLS: accepted protocol versions (TLS 1.0/1.1 deprecated per RFC 8996), weak ciphers (RC4, EXPORT, NULL, DES), DHE < 2048-bit. Use `sslscan` or `openssl s_client`.
- HSTS present? `max-age ≥ 31536000`?
- Cookie flags `Secure`/`HttpOnly`/`SameSite`.
- Secrets in source/headers/repos (trufflehog, ast-grep `*-secret-*`, `*-jwt-*-secret`).

## Cryptographic storage — remediation
- Encrypt sensitive data at rest with **AES-256-GCM** (authenticated) or **ChaCha20-Poly1305**. Never ECB.
- Use the platform crypto library; never roll your own.
- Passwords → hashing, not encryption (see `kb/auth-session/`).
- Random values from a **CSPRNG** (`secrets`, `crypto.randomBytes`, `crypto/rand`) — never `Math.random`/`rand()`. Smells: `*-rand-not-crypto`, `vibe-js-math-random-crypto`.

## Transport (TLS)
- TLS 1.2+ only; prefer TLS 1.3. Disable TLS 1.0/1.1, SSLv3.
- Strong cipher suites, forward secrecy (ECDHE); disable RC4/3DES/EXPORT/NULL.
- Valid cert chain; HSTS with long `max-age` + `includeSubDomains` (+ preload when ready).
- Redirect HTTP→HTTPS; never send session cookies without `Secure`.

## Secrets management
- No secrets in code, config, env-committed files, logs, or images. Smells: `*-secret-hardcoded*`, `*-env-fallback-secret`, `console-log-credential`.
- Store in a **secrets manager** (Vault, cloud KMS/Secrets Manager); inject at runtime.
- Rotate on exposure and on schedule; scope least-privilege; audit access.

## Key management
- Separate keys per purpose/environment; store in an HSM/KMS.
- Defined rotation and revocation; never hardcode keys or check them into VCS.

## Verify the fix
Re-scan TLS (weak protocols/ciphers gone), confirm HSTS header, re-check cookie
flags, and confirm the rotated secret is no longer valid.
