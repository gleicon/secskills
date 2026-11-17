# Reporting & compliance

secskills produces three report formats from the same findings, plus an auditor
report and a re-test delta, for any target: a domain, a sandbox, a repository, or
a network block. Reports render offline from stored findings and evidence; they
never contact the target. Reports are written for a technical CISO who must split evidence across
teams and use the document as audit evidence.

## Formats

| Format | Command | Use |
|--------|---------|-----|
| Markdown | `secskills report --render <target>` | Terminal / repo / hand-off. Full sectioned report. |
| HTML | `secskills report --html <target> --output f.html` | Web view; source for PDF. |
| PDF | `secskills report --pdf <target> --output f.pdf` | Big-4-style deliverable. Needs headless Chrome/Chromium. |
| Auditor | `secskills report --audit <target>` | Control objectives, test ledger, attestation. |
| Re-test | `secskills report --retest <target>` | fixed / still-present / regressed vs the last run. |

If no headless browser is present, `--pdf` writes the HTML and tells you to use
your browser's Print-to-PDF. Check with `secskills doctor --category report`.

## Report structure (HTML/PDF)

1. Cover + classification
2. Document control (frameworks, compliance mapping, confidentiality)
3. Executive summary — risk narrative, **risk heat-map**, key findings, coverage
4. Methodology & scope
5. Findings summary table (ID, severity, CVSS, OWASP, **owning team**)
6. Detailed findings — per finding: affected asset, OWASP, CWE, CVSS 3.1 vector and score, CVEs,
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

## Evidence & risk model (CISO-grade)

secskills separates **severity** from **confidence**, and states how each finding
was validated — so a reader can trust the rating:

- **Confidence:** Confirmed · High · Medium · Low.
- **Validation:** exploited · behavior-confirmed · version-inferred · config-inferred · passive.
- **CVSS v3.1:** a real computed base vector + score (`CVSS:3.1/AV:N/.../ = 5.3`), not a band.
- **Applicability:** a missing header on a non-HTML/API endpoint is an INFORMATIONAL
  *hardening deviation*, not a MEDIUM vulnerability. CSP/clickjacking are rated on
  HTML responses only; `ACAO:*` is elevated only with `Allow-Credentials: true`.
- **Component CVEs are leads, not proof:** version→CVE correlation is `version-inferred`,
  capped at MEDIUM, titled "manual validation required" — hiding a banner is not remediation.
- **/metrics is deep-inspected:** severity follows what actually leaked (a
  validated credential → HIGH; a credential-like pattern or internal topology →
  MEDIUM; generic runtime metrics → LOW).
- **Network blocks** add a network inventory (hosts, services, reachable
  datastores). Banner-version CVE matches are leads (LOW, or MEDIUM when a CVE is
  in CISA KEV); open or default-credential datastores are HIGH.
- **Root issues:** many per-host observations collapse into a few root issues
  ("163 observations → a handful of platform/edge issues").
- **Deliverable naming:** "External Attack Surface & Security Assessment" unless a
  genuine exploit/validation phase ran (then "Penetration Test").
- **Provenance & authorization:** every report states how tested hosts were
  discovered and the authorization basis; cross-domain OSINT pivots are reported
  separately and require scope confirmation before inclusion.

## Data artifacts

The target's workdir holds the raw data behind the report (subdomains, live
hosts, findings, evidence objects, Shodan data, nuclei output, screenshots, and
for blocks the observations). It is created readable by you only. Treat it and
`~/.secskills-findings/` like a credentials store; never commit engagement data.
