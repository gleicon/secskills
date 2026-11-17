# Security model

secskills runs inside LLM-enabled environments (Claude Code, opencode, MCP) and
tests systems you authorize. It is hardened on two fronts: it must not be abused
to attack unauthorized targets, and it must not let a target abuse the LLM that
reads its output.

## Authorization & scope

- Every target-touching command (`discover`, `test`, `sandbox`, `watch`,
  `integrity`, `enrich`, `leakcheck`, `dbcheck`) refuses without `--confirm` or an
  authorized `.secskills-scope.yml`. Network blocks are authorized per IP, and
  `out_of_scope` entries are never scanned. Scope files are honored only when owned by the invoking
  user and not group/other-writable (a planted file cannot authorize).
- Non-destructive by default; `--intrusive` needs a second confirmation.
- DoS and mass third-party scanning are always refused.
- Every probe is scope-confined; discovered-but-out-of-scope hosts are skipped.

## Prompt-injection defense (target → LLM)

Everything collected from a target is untrusted and may try to hijack the reading
model. Defense in depth:

1. **Native neutralization (always on).** Every target-derived string (page
   titles, server headers, DNS names, Shodan output, nuclei names) passes through
   `textutil.NeutralizeUntrusted`: strip invisible/bidi/zero-width/control code points and
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
- Every target-derived value in a reproduction command shown in a report is
  shell-quoted, so a pasted command cannot be hijacked; hostnames are validated
  (ASCII, no metacharacters) at discovery.

## Network guards

- Outbound fetches (including the MCP `fetch` tool) reject non-http(s) schemes
  and hosts resolving to private, loopback, link-local, metadata, or reserved
  ranges, and cap response size. The network-mode probe client re-checks every
  address at connect time to defeat DNS rebinding.
- Probes never follow redirects.
- Requests carrying operator credentials verify TLS; `--insecure-auth` is an
  explicit opt-out for self-signed targets.
- Reports, tickets, and exports never contact the target; a test forbids every
  outbound connection while rendering.

## Data handling

- The findings store (`~/.secskills-findings/`) and per-target workdirs are
  created readable by the operator only; a workdir that is a symlink or owned by
  someone else is refused. Treat them like a credentials store; never commit them.
- Reports carry the fact of an exposure and key names, never credential values.
- PII is scrubbed from reports (`secskills scrub`, tldt).

## Reporting an issue

Keep it private. Do not describe a vulnerability, or include any target data,
in a public issue, discussion, pull request, or commit. Contact the maintainer
directly via the GitHub profile of the repository owner; a person reads and
triages every report by hand. There is no automated intake.

Never include engagement data (findings, evidence, workdirs, scope files,
credentials) in a report about secskills itself.
