---
class: auth-session
owasp_top10: A07:2021 — Identification and Authentication Failures
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Authentication, url: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html}
  - {name: Password Storage, url: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html}
  - {name: Session Management, url: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html}
  - {name: JSON Web Token for Java (JWT), url: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html}
  - {name: Multifactor Authentication, url: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html}
  - {name: Credential Stuffing Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html}
  - {name: Forgot Password, url: https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html}
---

# Identification & Authentication Failures (A07)

## Detection
- Account-lockout consistency: send ≤5 bad passwords (D-6 bound), check for lockout / uniform responses.
- Login/reset user enumeration: differing responses for existing vs non-existing accounts.
- Session token: entropy, JWT algorithm/claims, fixation (pre-login token valid post-login), timeout, cookie flags.
- Credential-stuffing exposure: no MFA + no rate limit + no anomaly detection.

## Password storage — remediation
- Hash with a **memory-hard, salted** algorithm: **Argon2id** (preferred), else **scrypt** or **bcrypt** (cost ≥ 10), or **PBKDF2** with a high iteration count where required.
- Unique per-user salt (built into the above); optional server-side **pepper** in a secret store.
- Never MD5/SHA-1/unsalted SHA-256 for passwords. Never reversible encryption.

## Authentication
- Enforce strong, breach-checked passwords (NIST 800-63B); length over composition rules.
- **MFA** for sensitive/admin access; TOTP/WebAuthn over SMS.
- Generic error messages ("invalid username or password") — no user enumeration.
- Rate-limit and progressively delay/lock after failed attempts; monitor credential stuffing.

## Session management
- Generate a new, high-entropy session ID at login; **regenerate on privilege change** (prevents fixation).
- Cookies: `Secure`, `HttpOnly`, `SameSite=Lax|Strict`; narrow `Domain`/`Path`; session-scoped where possible.
- Absolute + idle timeouts; invalidate server-side on logout.

## JWT
- Pin the algorithm server-side; reject `alg: none` and RS256→HS256 confusion.
- Strong signing key from a secret store; short expiry + rotation; validate `iss`/`aud`/`exp`.
- Don't put secrets in the payload (it's base64, not encrypted). Prefer opaque session tokens when revocation matters.

## Forgot-password
- Uniform response regardless of account existence; time-limited single-use token; no password in email; invalidate sessions on reset.

## Verify the fix
Re-run enumeration/lockout/fixation probes; expect uniform responses, enforced
lockout/rate-limit, rotated session ID, and correct cookie flags.
