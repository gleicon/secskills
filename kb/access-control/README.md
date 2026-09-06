---
class: access-control
owasp_top10: A01:2021 — Broken Access Control (+ A04 Insecure Design)
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Authorization, url: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html}
  - {name: Insecure Direct Object Reference Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html}
  - {name: Cross-Site Request Forgery Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html}
  - {name: Access Control (Authorization) Testing, url: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html}
---

# Broken Access Control (A01)

The #1 category. Enforcement gaps let a user act outside intended permissions:
vertical (privilege escalation) or horizontal (another user's data, IDOR).

## Detection
- Request protected routes unauthenticated (`/api/admin`, `/api/users`) — expect 30x to login, not 200 with data.
- IDOR: change an identifier (`/api/users/1` → `/api/users/2`) with a valid low-priv token; a 200 with another user's data is the finding.
- Priv-esc: call admin-only endpoints with a standard token.
- Force-browse to functions hidden in the UI but not enforced server-side.

## Remediation — Authorization
- **Deny by default.** Every request authorizes against a central policy; no endpoint is open unless explicitly allowed.
- **Enforce server-side**, never trust client-side role checks or hidden fields.
- **Verify ownership** on every object access — bind the resource to the session subject; do not trust IDs from the request.
- Prefer **RBAC/ABAC** with a single enforcement point (middleware/filter), not scattered per-handler `if` checks.
- Log access-control failures; rate-limit to blunt enumeration.

## IDOR
- Use access-control checks keyed to the authenticated user for every object reference.
- Where feasible use **indirect references** (per-session mapping) or unguessable IDs (UUIDv4) — but unguessable IDs are defense-in-depth, **not** a substitute for the ownership check.

## CSRF
- Prefer framework built-in CSRF protection.
- **Synchronizer token** (per-session/per-request, verified server-side) or the double-submit-cookie pattern.
- Set `SameSite=Lax` (or `Strict`) on session cookies as defense-in-depth.
- For state-changing APIs consuming JSON with a custom header, require that header (browsers can't set it cross-origin without CORS).

## Verify the fix
Repeat the bypass/IDOR request; expect 401/403 or a redirect, and no cross-user data.
