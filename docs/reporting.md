# Reporting & compliance

secskills produces three report formats from the same findings, plus a re-test
delta. Reports are written for a technical CISO who must split evidence across
teams and use the document as audit evidence.

## Formats

| Format | Command | Use |
|--------|---------|-----|
| Markdown | `secskills report --render <target>` | Terminal / repo / hand-off. Full sectioned report. |
| HTML | `secskills report --html <target> --output f.html` | Web view; source for PDF. |
| PDF | `secskills report --pdf <target> --output f.pdf` | Big-4-style deliverable. Needs headless Chrome/Chromium. |
| Re-test | `secskills report --retest <target>` | fixed / still-present / regressed vs the last run. |

If no headless browser is present, `--pdf` writes the HTML and tells you to use
your browser's Print-to-PDF. Check with `secskills doctor --category report`.

## Report structure (HTML/PDF)

1. Cover + classification
2. Document control (frameworks, compliance mapping, confidentiality)
3. Executive summary — risk narrative, **risk heat-map**, key findings, coverage
4. Methodology & scope
5. Findings summary table (ID, severity, CVSS band, OWASP, **owning team**)
6. Detailed findings — per finding: affected asset, OWASP, CWE, CVSS band, CVEs,
   **SOC 2 / ISO 27001 / PCI-DSS controls**, owning team, impact, evidence, remediation
7. Compliance coverage matrix
8. Evidence index (screenshots, raw data)

## Splitting work across teams

Every finding carries an **owning team** (Platform/Edge, AppSec, IAM, SecOps,
Application teams, Mobile, AI/ML). The findings summary table and compliance
matrix are sortable by team so each group gets its slice. Raw `data/findings-*.json`
supports custom filtering.

## Compliance mapping

Each finding maps to the controls it is evidence for:

| Domain | SOC 2 (TSC) | ISO 27001:2022 | PCI-DSS 4.0 |
|--------|-------------|----------------|-------------|
| Misconfiguration / exposure | CC6.1, CC6.6, CC7.2 | A.8.20, A.8.9 | 1.2/1.3, 2.2 |
| Cryptography / transport | CC6.1, CC6.7 | A.8.24, A.5.33 | 4.1/4.2 |
| Vulnerable components | CC7.1, CC8.1 | A.8.8, A.8.19 | 6.3.1/6.3.2 |
| Access control | CC6.1–6.3 | A.5.15, A.8.3 | 7.1/7.2 |
| Authentication / session | CC6.1–6.3 | A.5.17, A.8.5 | 8.2/8.3 |
| Injection | CC7.1, CC8.1 | A.8.28, A.8.26 | 6.2.4 |
| Logging / monitoring | CC7.2–7.4 | A.8.15, A.8.16 | 10.2/10.3 |

These references indicate the criteria a finding is relevant to — evidence
support for an audit, not an audit opinion.

## CVSS

secskills reports an **indicative CVSS v3.1 band** per severity (Critical 9.0–10.0,
High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9). Per-finding vectors are a manual
follow-up; component CVEs carry their OSV identifiers.

## Data artifacts

Alongside the report: `data/subs-*.txt`, `data/live-*.json`, `data/findings-*.json`,
`data/shodan/`, `nuclei.jsonl`, and `screenshots/`. These are **sensitive** — treat
like a credentials store; never commit engagement data.
