# Reviewing source code

Static review of a repository with the embedded ast-grep rules: real
vulnerability sinks and common smells in AI-written code, across Go, JavaScript,
TypeScript, Python, PHP, and Ruby. No network, no authorization gate.

## Before you start

- `ast-grep` on PATH (`secskills doctor --tools ast-grep` prints the install command).

## Scan

```bash
secskills source ./my-service                 # human-readable, grouped by rule
secskills source --json ./my-service > sast.json
```

The 117 rules live under `sinks/` (injection, deserialization, SSRF, path
traversal, hard-coded secrets) and `vibe/` (commented-out auth, disabled CSRF,
CORS wildcards, `Math.random` for tokens, TLS verification turned off,
debug-mode bypasses). The rules ship inside the binary; nothing to download.

## Triage

A match is a lead. For each one, follow untrusted input from where it enters to
the flagged line and confirm it is reachable and unsanitized. Skip test fixtures
and string literals. `error`-level injection, XSS, and secret matches first.

For the fix, read the guidance and a working example for your stack:

```bash
secskills kb injection
secskills recipes injection            # secure vs vulnerable code for Node, Python, Go
```

## Keep confirmed findings with the rest of an engagement

```bash
secskills findings add --target my-service --id SRC-01 \
  --title "SQL injection in search handler" --host internal/search/handler.go:42 \
  --severity HIGH --status manual
secskills findings write-run --target my-service
secskills report --render my-service
secskills export --format sarif my-service --output my-service.sarif
```

## In CI

`source` exits 0 when the scan ran, with or without findings, and non-zero only
when it could not run. Gate on the JSON:

```yaml
- name: secskills source review
  run: |
    go install github.com/gleicon/secskills/cmd/secskills@latest
    secskills source --json . > sast.json
    errors=$(jq '[.[] | select(.severity == "error")] | length' sast.json)
    echo "error-level matches: $errors"
    test "$errors" -eq 0
```

Install `ast-grep` in the job first (for example `cargo install ast-grep --locked`
or your platform's package).
