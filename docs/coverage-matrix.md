# Coverage matrix — skills × tools × results × OWASP × output

The organizing map: how a secskills stage ties tools → results → OWASP cheat
sheets → report output, aligned to the Pentest Reporting Playbook's 8-section
anatomy and 8-field finding. Use it to see, for any stage, what runs, what it
produces, and where it lands in the report.

## A. Stage → skill/command → tools → result → OWASP → report section

| Stage | Command / skill | Tools | Result artifact | OWASP class(es) | Report section |
|-------|-----------------|-------|-----------------|-----------------|----------------|
| Intake | `secskills-intake`, `profile`, `scope` | subfinder, dnsx, shodan (passive) | `ENGAGEMENT.md`, `.secskills-scope.yml`, profile | — | Cover & doc control · Scope & RoE |
| Discover | `discover` / `secskills-discover` | subfinder, amass, dnsx, httpx, shodan | `subs.txt`, `resolved.txt`, `live_hosts.json`, `ips.txt`, `shodan/` | A05 (exposure signals) | Scope · Attack Surface · OSINT |
| Source | `source` / `secskills-source` | ast-grep, semgrep | ast-grep findings | A01/A02/A03/A06 (per rule) | Detailed findings |
| Test — headers | `test` (checkSecurityHeaders) | native | findings (A05/A02) | config-exposure, crypto-secrets | Summary matrix · Detailed findings |
| Test — TLS | `test` (checkTLS) + `--deep` sslscan | native, sslscan | findings (A02) | crypto-secrets | Detailed findings |
| Test — exposure | `test` (checkExposure) | native | findings (A05/A09) | config-exposure, logging-monitoring | Detailed findings |
| Test — components | `test` (cveLookup) | OSV API | findings (A06) + CVE IDs | components-supply-chain | Detailed findings · Component CVE |
| Test — deep | `test --deep` | nuclei, sslscan, ffuf/native, httpx-screenshot | `nuclei.jsonl`, `screenshots/` | per template | Detailed findings · Evidence index |
| Test — authed | `test --auth-token/--cookie` | native | findings (A01/A07) or "not available" | access-control, auth-session | Authenticated testing |
| Sandbox | `sandbox` | docker + test engine | findings on isolated instance | per check | Detailed findings |
| Report | `report --render/--html/--pdf` | native + chrome (PDF) | md / html / pdf | all | (the whole document) |
| Re-test | `report --retest` | native structured probes | run delta | — | Remediation tracker |
| Interop | `export --format sarif\|cyclonedx`, `tickets` | native | SARIF 2.1.0, CycloneDX 1.5 + VEX, CSV/JSON rows | all | — (CI / tracker) |
| Exposure — sweep | `discover --cidr/--asn` | native rate-gated TCP connect scan | `observations.jsonl` | — | Exposure report: inventory |
| Exposure — enrich & leaks | `enrich`, `leakcheck`, `dbcheck`, `kprobe` | native banners, HTTP, RESP/OP_MSG, mysql client | `enriched-observations.jsonl`, `leaks.jsonl`, `dbcheck.jsonl` | config-exposure, components-supply-chain | Exposure report §1–2 |
| Exposure — CVE join | `feed kev/epss/nvd`, `cvematch`, `lifecycle` | CISA KEV, FIRST EPSS, NVD 2.0 | `candidates.jsonl`, `findings.jsonl` | components-supply-chain | Exposure report §3 |
| Exposure — report | `prefix-report`, `deliver` | native | `exposure-report.md`, `feed-<tenant>.json` | all | (the block report) |

## B. The 8-field finding (playbook §03) → secskills source

| Finding field | secskills source | Status |
|---------------|------------------|--------|
| Title (specific noun phrase) | `Finding.Title` from the check | ✔ |
| Severity + CVSS | `Finding.Severity` (written rubric) + CVSS 3.1 vector and base score (`CVSSVector`) | ✔ |
| Affected asset (exact) | `Finding.Host` (URL/host or file:line) | ✔ |
| Description (fact) | `impactFor(kbClass)` | generic per class |
| Business impact (non-engineer) | **business-risk one-liner** (added) | ✔ (added) |
| Proof of concept (reproducible) | `Finding.EvidenceCmd` | ✔ |
| Remediation (assignable) | `kbRemediation(kbClass)` from the cheat sheet | ✔ (cheat-sheet-driven) |
| References (CWE/CVE) | `Finding.CWE`, `Finding.CVEs`, `References` | ✔ |

## C. The 8-section report anatomy (playbook §02) → secskills

| # | Section | secskills | Status |
|---|---------|-----------|--------|
| 1 | Cover & document control | report cover + doc-control table | ✔ |
| 2 | Executive summary (both audiences, strengths too) | exec summary + controls-held | ✔ |
| 3 | Scope & rules of engagement | scope section + `.secskills-scope.yml` | ✔ |
| 4 | Methodology (named + cited) | methodology section, WSTG/PTES cited | ✔ |
| 5 | Summary matrix of findings (FND-IDs) | risk summary table (`F-NNN`) | ✔ |
| 6 | Detailed findings (8 fields) | detailed findings | ✔ |
| 7 | **Attack narrative** (chaining) | **added** — chained-exposure narrative | ✔ (added) |
| 8 | **Appendices & cleanup log** | **added** — tools used + cleanup log (non-destructive attestation) | ✔ (added) |

## D. Severity heuristic (playbook §04)

- CVSS v3.1 bands: Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0.
- Gut-check adjustments encoded in `severityHeuristic`: remote + no-auth **+2 tiers**;
  requires local/creds **−1**; needs social-eng/race **−1**; full asset compromise **+1**.

## E. Output items beyond the report

| Output | Command | Playbook driver |
|--------|---------|-----------------|
| Ticket export (fields = ticket fields) | `secskills tickets <target>` | §05 "make finding fields your ticket fields" |
| Remediation SLA by severity | in report (Critical 7d / High 30 / Med 90 / Low next release) | §05 "track SLA by severity" |
| Retest verification note (append, don't reissue) | `report --retest` appends to finding | §05 "close the loop in writing" |
| OWASP cheat-sheet remediation (shared library) | `kbRemediation` — CISA-library analog | §05 "fork CISA's finding library" |

## F. OWASP cheat-sheet ↔ result cross-reference

Every finding's `kb_class` selects the cheat sheet that supplies detection intent
and remediation text: `injection` · `access-control` · `auth-session` ·
`crypto-secrets` · `config-exposure` · `components-supply-chain` · `ssrf-xxe` ·
`files-deserialization` · `logging-monitoring` · `mobile` · `llm-agents`. The
report's Detailed Findings pull remediation directly from `kb/<class>` (not a
template), and the Testing Direction section keys next steps to the same classes.
