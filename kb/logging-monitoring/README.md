---
class: logging-monitoring
owasp_top10: A09:2021 — Security Logging and Monitoring Failures
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Logging, url: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html}
  - {name: Application Logging Vocabulary, url: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html}
---

# Security Logging & Monitoring Failures (A09)

Assessed indirectly from the outside: exposed `/metrics` (logs likely
unprotected too), verbose error messages (unsanitized logging), public
health/uptime endpoints leaking version state.

## What to log
- Authentication (success + failure), access-control failures, input-validation
  failures, session lifecycle, privilege changes, and high-value transactions.
- Enough context to investigate: timestamp (UTC), event type, actor, source IP,
  outcome — using a consistent vocabulary (OWASP Application Logging Vocabulary).

## How to log (remediation)
- **Never log secrets or sensitive PII** — no passwords, tokens, session IDs,
  card/PAN, full request bodies. Smells: `console-log-credential`.
- Neutralize untrusted data before logging to prevent **log injection/forging**
  (strip CR/LF, encode); treat logs as an integrity-sensitive record.
- Centralize logs on a protected, access-controlled, tamper-evident store with
  retention; time-sync sources.
- **Alert** on auth-failure spikes, access-control failures, and known-attack
  signatures; define response playbooks.
- Don't expose log/metrics/monitoring endpoints unauthenticated (see `kb/config-exposure/`).

## Verify the fix
Trigger an auth failure and an access-control failure → both appear in the log
with actor/outcome and no sensitive values; confirm the alerting path fires.
