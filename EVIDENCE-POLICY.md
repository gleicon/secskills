# secskills — Evidence Handling & Governance Policy

This policy governs the evidence secskills produces so an external auditor can
rely on it. It complements the technical controls already in the engine (immutable
evidence objects, run attestation, cryptographic signing).

## 1. Evidence model

- **Raw observation is the system of record.** Findings are derived assertions
  over immutable evidence objects (`evidence/EV-*.blob`, indexed in
  `evidence-manifest.jsonl`). Each object is content-addressed and append-only.
- **The PDF/HTML report is a view, not the record.** Regenerating a report from
  the same run and evidence is deterministic.
- Every finding carries a stable `finding_key` (detector + normalized asset +
  control) so its history is traceable across runs.

## 2. Integrity & origin

- Each run emits `run-meta.json` with SHA-256 over findings, the normalized scope
  manifest, the ruleset (detector pack), the raw-evidence bundle, and the run
  config, plus the engine build commit and scanner source IP.
- Runs are signed with an ed25519 key (`secskills attest --sign`); verifiers use
  `secskills attest --verify`. The signature proves origin; the hashes prove
  integrity.

## 3. Redaction

- Credential-like values are masked in sampled evidence before storage
  (`redaction_status: redacted`). Detectors flag credential-like patterns as
  *unvalidated* — never asserted as confirmed secrets without manual validation.
- Screenshots may contain PII; treat the evidence bundle as sensitive (see §5).

## 4. Retention

- Default retention: **12 months** for run records and evidence bundles, unless a
  governing engagement contract specifies otherwise.
- Evidence bundles are retained encrypted at rest by the operator; secskills does
  not transmit evidence to any third party.

## 5. Access & residency

- Evidence lives under the operator's `~/.secskills-findings/<target>/` and the
  engagement workdir. Access is limited to the assessment team and the authorized
  recipients named on the report cover.
- Evidence residency follows the operator's storage location; the engine performs
  no off-host storage.

## 6. Deletion & tamper-evidence

- Deletion is operator-controlled (remove the target's store directory and
  engagement workdir).
- Tampering is detectable: any change to `run-meta.json` after signing fails
  `attest --verify`; changing an evidence object changes its content hash and the
  bundle hash recorded in the attestation.

## 7. Human adjudication

- Automated severity is immutable. A reviewer adjudication is recorded separately
  (`secskills override`) with reviewer, timestamp, reason, and optional evidence
  ref; the report shows both the automated and the reviewed severity.

## 8. Scope discipline

- Only authorized targets are tested. Cross-domain pivots discovered via OSINT are
  recorded with provenance and marked NOT AUTHORIZED / discovery-only; no active
  probes are sent to them.
