# Security model

secskills runs inside LLM-enabled environments (Claude Code, opencode, MCP) and
tests systems you authorize. It is hardened on two fronts: it must not be abused
to attack unauthorized targets, and it must not let a target abuse the LLM that
reads its output.

## Authorization & scope

- Live and sandbox modes refuse without `--confirm` or an authorized
  `.secskills-scope.yml`. Scope files are honored only when owned by the invoking
  user and not group/other-writable (a planted file cannot authorize).
- Non-destructive by default; `--intrusive` needs a second confirmation.
- DoS and mass third-party scanning are always refused.
- Every probe is scope-confined; discovered-but-out-of-scope hosts are skipped.

## Prompt-injection defense (target → LLM)

Everything collected from a target is untrusted and may try to hijack the reading
model. Defense in depth:

1. **Native neutralization (always on).** Every target-derived string (page
   titles, server headers, DNS names, Shodan output, nuclei names) passes through
   `neutralizeUntrusted`: strip invisible/bidi/zero-width/control code points and
   Unicode tag chars, redact injection patterns (`ignore previous`, fake `system:`
   turns, tool-call bait, staged exfil), and collapse newlines so a value cannot
   fake a conversational turn. No target string reaches a finding, report, or
   stdout unneutralized.
2. **Detection + finding.** Collected artifacts are scanned; injection content is
   recorded as a MEDIUM finding (CWE-77 / A03) so it is surfaced, not silently
   dropped.
3. **tldt layer (when present).** `tldt --detect-injection`/`--sanitize-pii` adds
   an independent detection and PII-redaction pass.
4. **Reports fence untrusted data** and state that target strings are neutralized.

## Command execution

- No `sh -c` / `eval` of stored data anywhere in the Go binary. Retest re-verifies
  each finding with a structured Go probe. `EvidenceCmd` is human-readable only.
- Every target-derived value that appears in a shell reference script is
  shell-quoted; hostnames are validated (ASCII, no metacharacters) at discovery.

## SSRF

- The MCP `fetch` tool rejects non-http(s) schemes and hosts resolving to
  private/loopback/link-local/reserved ranges (checked post-resolution to defeat
  DNS rebinding), and caps response size.

## Data handling

- The findings store (`~/.secskills-findings/`) and engagement data are sensitive
  — treated like a credentials store; excluded from git.
- PII is scrubbed from reports (`secskills scrub`, tldt).

## Reporting an issue

Open a private report to the maintainer. Do not file target findings publicly.
