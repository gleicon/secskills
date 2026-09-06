---
name: secskills-report
description: "Assemble the findings report from any mode (source/sandbox/live) using the standard template, and run re-test/delta against a prior run. Produces a human-readable markdown report — severity, evidence, affected surface, and OWASP-cheat-sheet-keyed remediation — plus fixed/still-present/new status on retest."
disable-model-invocation: true
---

Turn collected findings into a report a human can act on, and track them across
runs. Template, finding format, remediation phases, and glossary live in
`lib/report-template.md`; the findings store and retest loop in
`lib/findings-store.sh` (D-3, D-4).

## Report generation

1. Read findings from `$SECSKILLS_WORKDIR/findings.json` (live/sandbox) and/or
   the static findings list (source mode).
2. Render the full structure from `lib/report-template.md`: header, executive
   summary (risk narrative + counts + strengths + systemic issues + phased
   roadmap), surface, fingerprint, attack narrative, detailed findings, risk
   table, Top 10 coverage matrix, OSV component analysis, tools/methodology,
   glossary (appended verbatim from `vendor/redteam-pentest.md`).
3. Every finding uses the Finding Format and names the `kb/` cheat sheet that
   keyed its remediation.
4. **PII scrubbing:** never emit extracted emails/names/personal data — report
   the category ("maintainer email disclosed"), not the value. Run every
   evidence blob through `secskills_scrub_pii` (`lib/tldt.sh`) before it enters
   the report; it redacts emails, API keys, tokens, JWTs, SSNs, and cards.
5. Write to `./<target>_secskills_report.md` (or `--output <path>`).

## Persisting findings (D-4)

If `--save-findings`, `source lib/findings-store.sh` and call
`secskills_write_run <target>` — freezes `findings.json` into
`~/.secskills-findings/<target>/run-<id>.json` and updates `latest`. The store
holds sensitive findings: treat like a credentials store, never commit public.

## Re-test / delta (FR-10)

`--retest <target>`: skip discovery, `source lib/findings-store.sh`, call
`secskills_retest <target>`. It re-runs each finding's `evidence_cmd`, classifies
**open / mitigated / regressed** (with response-hash drift detection), writes a
new run file, and prints the delta table. To diff two arbitrary runs, use the
comparison loop in `vendor/redteam-pentest.md` §8.5.

## Output

The report path, the finding counts by severity, and — on retest — the
fixed/still-present/new/regressed summary.
