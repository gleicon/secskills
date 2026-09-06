# Report template (lifted from redteam-pentest, D-3)

`secskills-report` assembles a single markdown report at the output path
(default `./<target>_secskills_report.md`). Findings across all three modes
(source / sandbox / live) feed the same template.

## Report structure

```
# Security Assessment Report: <TARGET>

**Classification:** Confidential — Authorized Recipients Only
**Report Version:** 1.0
**Date:** <YYYY-MM-DD>
**Test Window:** <start> to <end>
**Scope:** <targets>
**Mode(s):** source | sandbox | live (list those run)
**Type:** External Black-Box (or grey/white per flag)
**Credentials:** None / <role + privilege if authenticated>
**Intrusive tests:** disabled | enabled
**Authorization:** Confirmed by <user> at <timestamp>
**Tools:** <detected tools actually used>
**Frameworks:** OWASP Top 10 2021, OWASP WSTG v4.2, OWASP Cheat Sheet Series, MITRE ATT&CK, NIST SP 800-53, CWE

---

## Executive Summary
[3–5 sentence risk narrative: overall level, worst findings, whether exploitation
was demonstrated, systemic root-cause pattern. Not a finding list.]

**Finding Counts:** table CRITICAL/HIGH/MEDIUM/LOW/INFO/Total
**Security Strengths:** [what the tester could NOT do — controls that held]
**Systemic Issues:** [isolated bugs vs systemic failure]
**Strategic Remediation Roadmap:** Phase 1 (immediate) / 2 (short) / 3 (long)

---

## 1. Target Overview            [DNS/MX/TXT/ASN for live; repo/build for source/sandbox]
## 2. Attack Surface             [subdomains + live services table, or source tree/routes]
## 3. Infrastructure Fingerprint [tech map: Host, Technology, Version, Evidence, Risk]
## 4. Attack Narrative           [chronological story of the engagement, past tense, chains]
## 5. Detailed Findings          [one subsection per finding — Finding Format below]
## 6. Risk Summary Table         [all findings, sorted by severity]
## 7. OWASP Top 10 Coverage Matrix
## 8. Component CVE Analysis (OSV)
## 9. Tools and Methodology
## Glossary                      [append verbatim — see below]

---
**Handling:** sensitive findings. Distribute need-to-know, encrypted channels only.
```

## Finding Format (all fields required; N/A where not applicable)

```
### FINDING-NN — <Title>

**Host/Location:** <URL, or file:line for source mode>
**Severity:** CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
**CWE:** CWE-NNN — <weakness>
**CVSS v3.1 Base:** <vector> — Score: N.N
**Exploitation Difficulty:** LOW / MEDIUM / HIGH — <one-line rationale>
**OWASP 2021:** A0N — <category>
**MITRE ATT&CK:** T<id> — <technique> (or N/A)
**NIST SP 800-53:** <control ID> — <name>
**OWASP Cheat Sheet:** <sheet name + kb/ path that keyed the remediation>
**Instances:** N
**Retest Status:** Open / In Progress / Fixed / Accepted Risk
**Remediation Complexity:** LOW / MEDIUM / HIGH
**Remediation SLA:** Immediate / Short-term / Medium-term / Long-term

#### Tests Conducted     [technique/tool/observation that triggered it]
#### Description         [technical description]
#### Evidence            [exact reproducing command + exact output; redact creds]
#### Impact              [Technical / Business / Attack Chain]
#### Remediation         [specific fix + verification, keyed to the cheat sheet]
#### References          [CVE, CWE, NIST, MITRE, WSTG id, OSV, cheat-sheet URL]
```

Every finding's remediation is keyed to a `kb/` cheat-sheet entry — that is what
grounds secskills over a bare scanner.

## Remediation phase structure (complexity-based, not time-based)

- **Phase 1 — Immediate:** config-only, reversible, no code change (firewall/ACL, disable public access).
- **Phase 2 — Short-term:** low-complexity code/config (headers, endpoint auth gate, non-breaking upgrade).
- **Phase 3 — Medium-term:** auth-flow redesign, secret rotation with dependents, network arch changes.
- **Phase 4 — Long-term:** architectural/process (split-horizon DNS, CT monitoring, secrets manager adoption, CI security gates).

## Glossary

Append the glossary from `vendor/redteam-pentest.md` (section "## Glossary",
the fenced block) verbatim to every report. It defines ASN, CT log, CORS, CSP,
CVSS, IDOR, JWT, OIDC, OSV, SSRF, XSS, and the scoring terms used above.
