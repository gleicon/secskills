---
class: injection
owasp_top10: A03:2021 — Injection
license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)
source_project: OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org/)
snapshot: authored 2026-09-05 from the upstream index; refresh via tools/ingest.sh
bundled_cheatsheets:
  - {name: Injection Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html}
  - {name: SQL Injection Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html}
  - {name: Query Parameterization, url: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html}
  - {name: Cross Site Scripting Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html}
  - {name: DOM based XSS Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html}
  - {name: OS Command Injection Defense, url: https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html}
  - {name: LDAP Injection Prevention, url: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html}
---

# Injection (A03)

Untrusted input reaching an interpreter (SQL/NoSQL, OS shell, LDAP, template,
DOM). The defense is the same shape everywhere: keep code and data separate.

## Detection (what to test)
- Parameters reflected into responses (XSS) — crawl with katana, fuzz with dalfox.
- Error verbosity: `?q='` and `?q=<script>x</script>` — DB errors or unescaped reflection.
- String-built queries/commands in source (ast-grep `*-injection-*`, `*-xss-*`, `*-sql-*`).

## SQL injection — remediation (priority order)
1. **Parameterized queries / prepared statements.** Never concatenate input into SQL.
2. **Stored procedures** (when they do not build dynamic SQL internally).
3. **Allow-list input validation** for identifiers that cannot be parameterized (table/column names).
4. **Escaping** only as a last resort, DB-specific.
5. Least-privilege DB account; disable multi-statements.

Example — safe (parameterized):
```sql
-- BAD:  "SELECT * FROM users WHERE id = " + id
-- GOOD:
SELECT * FROM users WHERE id = ?      -- bind id as a parameter
```

## XSS — remediation
- **Context-aware output encoding** at the sink: HTML body, HTML attribute, JS,
  CSS, and URL contexts each need their own encoding.
- Prefer a framework's auto-escaping template; avoid `innerHTML`,
  `dangerouslySetInnerHTML`, `document.write`, `v-html`.
- **DOM XSS:** use safe sinks (`textContent`, `setAttribute`); treat
  `location`, `document.referrer`, `window.name`, `postMessage` data as untrusted.
- Defense-in-depth: a strong **Content-Security-Policy** (see `kb/config-exposure/`),
  `HttpOnly` session cookies, and a trusted-types policy where supported.
- Sanitize rich HTML with a vetted library (DOMPurify) — never a hand-rolled regex.

## OS command injection — remediation
- Avoid shelling out; use language-native APIs.
- If unavoidable: pass arguments as an **array** (no shell string), never
  interpolate input; allow-list the command and its arguments.
- ast-grep smells: `py-injection-subprocess-shell-true`, `*-injection-exec`,
  `*-injection-system`, `rb-injection-backtick`.

## LDAP / template / NoSQL
- LDAP: escape per RFC 4515 with the framework's LDAP-encoding routine; allow-list DN components.
- Template (SSTI): never render user input as a template; pass it as data. Smells: `py-injection-ssti-flask`, `py-injection-jinja2-from-string`.
- NoSQL: reject operator objects (`$where`, `$gt`) in user JSON; use typed queries.

## Verify the fix
Re-run the reproducing request; the payload should be returned inert (encoded)
or rejected, and no interpreter error should surface.
