---
name: secskills-source
description: "Static source review of code in a repo/path. Runs the bundled ast-grep rule set (real vulnerability sinks + AI/vibe-code anti-patterns across Go, JS, TS, Python, PHP, Ruby), then traces each hit to confirm exploitability and keys remediation to the OWASP knowledge base. No network traffic — no authorization gate required."
disable-model-invocation: true
---

Find exploitable weaknesses in source. Static and offline — sends no traffic, so
no authorization gate (FR-7.b). The finding engine is the vendored ast-grep rule
set under `rules/` (117 rules; `sinks/` real vulns + `vibe/` AI-code smells).

**Preferred:** run the binary — `secskills source <path>` runs the embedded
rules (no external rule files needed). For fixes with real code, `secskills
recipes <class>` gives per-stack (Node/Python/Go) secure-vs-vulnerable snippets.
The manual steps below apply when driving ast-grep directly.

## Procedure

1. **Scope.** Positional args are files/dirs/globs. With none, review the code
   changed on the current branch; `--full` reviews the whole tree.
2. **Structural scan (if `ast-grep` present, D-1):**
   ```bash
   ast-grep scan --config rules/sgconfig.yml <scope> --json \
     | jq -r '.[] | "\(.severity|ascii_upcase) [\(.ruleId)] \(.file):\(.range.start.line) — \(.message)"' \
     | sort
   ```
   If `ast-grep` is absent, note it and fall back to reading the code directly
   for the same sink patterns (grep-assisted).
3. **Trace every hit.** A rule match is a lead, not a finding. Follow untrusted
   input from entry to the flagged sink; confirm it is reachable and unsanitized
   before recording. Exclude string-literal / test-only matches.
4. **Triage (from the rule families):**
   - `error[*-injection-*]`, `error[*-xss-*]` → high priority, verify manually.
   - `error[*-secret-*]` → confirm it is a live secret; recommend rotation.
   - `error[vibe-*]` → AI/vibe-code smell (commented-out auth, disabled CSRF,
     CORS wildcard, `Math.random` crypto, TLS skip-verify, `DEBUG`/`NODE_ENV`
     bypass); check it is real, not test scaffolding.
   - `warning[*]` → review context; many are valid in non-user-input paths.
5. **Key remediation to KB.** Map each confirmed finding's class to `kb/`
   (injection→`kb/injection/`, xss→`kb/injection/`, secret→`kb/crypto-secrets/`,
   deserialization→`kb/files-deserialization/`, auth→`kb/auth-session/`,
   ssrf→`kb/ssrf-xxe/`) and pull the remediation text from there.

## Output

A findings list in the Finding Format of `lib/report-template.md`, each anchored
to `file:line`, severity-ranked, with KB-keyed remediation. Feed to
`/secskills-report`, or emit inline for a quick review. No `emit_finding` probe
command is meaningful for static findings — set them `status: manual` if stored.
