---
name: secskills-report
description: "Produce the findings report for any mode (source/sandbox/live/network), and retest a prior run. Markdown, HTML, PDF, or a short auditor report — severity, evidence, affected asset, and OWASP-cheat-sheet-keyed remediation — plus fixed/still-present/regressed status on retest, ticket rows, and SARIF/CycloneDX export."
disable-model-invocation: true
---

Turn stored findings into a report a person can act on, and track them across
runs. The binary renders everything offline from stored findings and evidence;
generating a report never contacts the target.

## Render

```bash
secskills report --render <target>                       # Markdown to stdout
secskills report --html <target> --output report.html
secskills report --pdf  <target> --output report.pdf     # needs Chrome/Chromium
secskills report --audit <target> --output audit.md      # control objectives, ledger, attestation
secskills report --lint <target>                         # check invariants before sending
```

The target is what was assessed: a domain, `sandbox-<tag>`, or a network block
such as `203.0.113.0/24`. Findings are read from the target's workdir, else from
the latest saved run. For findings recorded by hand, save a run first:
`secskills findings write-run --target <target>`.

## Retest

```bash
secskills report --retest <target>
```

Each finding is re-probed with a structured check (no shell) and marked fixed,
still present, regressed, inconclusive, or manual. A new run is saved.

## Hand off

```bash
secskills tickets <target> --format csv --output tickets.csv
secskills export --format sarif <target> --output findings.sarif
secskills findings set --target <target> --id <ID> --status accepted --note "why"
secskills override --target <target> --key <finding_key> --severity LOW --reason "why"
secskills attest --sign <target>
```

## Writing narrative by hand

When the operator wants extra prose (an attack narrative, a phased roadmap), use
the structure and finding format in `lib/report-template.md`, and the glossary in
`thirdparty/redteam-pentest.md` (section "Glossary").

**Personal data:** report the category ("maintainer email disclosed"), never the
value. Run any evidence you paste into prose through `secskills scrub <file>`.

## Output

The report path, finding counts by severity, and — on retest — the
fixed/still-present/regressed summary.
