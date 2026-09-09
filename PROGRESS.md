# secskills — build progress (weak → strong, no shallow)

Directive: build everything, deepen existing before new, track progress. New
capabilities that enable a next step get built inline; other net-new ideas are
listed at the bottom.

## Milestones

- [x] M1 — Technology fingerprint registry (data-driven, growable like Shodan/Wappalyzer)
  - [x] Embedded `fingerprints.json` ruleset (56 sigs: headers/cookies/body → tech, category, second-stage pack)
  - [x] Favicon-hash → technology lookup (mmh3), growable overlay
  - [x] `secskills fp list|add|import` (learn from engagements; ingest Wappalyzer/native datasets)
  - [x] Rewired service fingerprint + second-stage triggers to the registry
- [x] M2 — Runtime capability planner (stateful chaining: discover cap → decide → new probe → new evidence)
- [x] M3 — Persisted attack-graph edges (planner-graph.jsonl; in evidence bundle hash)
- [x] M4 — Adversarial ledger real instrumentation (advstats.go: measured per-probe counters)
- [x] M5 — Second-stage depth: fingerprint extracts service version → runtime planner OSV CVE-applicability chains per service
- [x] M6 — Engine self-measurement corpus (measure.go: local vuln+safe servers, per-detector precision/recall; caught a real SSTI bug)
- [ ] M7 — Self-hostable OAST collaborator (`secskills oast-server`) + wire SSRF/XXE validation
- [ ] M8 — Origin looking-glass depth (JARM fingerprint; Censys / passive-DNS adapters, key-gated)
- [ ] M9 — Interop exports (SARIF + CycloneDX/VEX)
- [ ] M10 — Continuous mode (`secskills watch`: scheduled retest + posture drift)
- [ ] M11 — Per-evidence signing (evidence manifest hash-chain + signature)
- [ ] M12 — Credentialed depth (authorized-exploit: BOLA/IDOR user-A-vs-B, session/JWT/cookie, OAuth flow)

## Status log
(append newest at top)

- M6 DONE — measure.go + `secskills measure`: local corpus of deliberately-vulnerable + deliberately-safe servers, runs the LIVE adversarial detectors, measures precision/recall/FP per detector. 7 detectors at 100/100. CAUGHT A REAL BUG: the SSTI arithmetic product constant was wrong (73819*91193 = 6731776067, not 6731738867) so the detector would never have fired in production — now fixed + gated by measure_test.go. Next: M7 self-hostable OAST collaborator.

- M5 DONE — fingerprintService extracts a service version (Server header/body) and sets a version= pivot; the runtime planner then runs an OSV CVE-applicability probe for that technology@version (version-inferred, MEDIUM cap). Depth-per-discovery chained end to end. Next: M6 engine self-measurement corpus.

- M4 DONE — advstats.go: every adversarial module records candidates/positive/inconclusive per-probe (advProbe/advHit/advInconc, mutex-guarded). Written to adv-stats.json (in evidence bundle); ledger renders measured denominators, not derived. Verified: jaxy.dev 59 candidate probes measured. Next: M5 second-stage depth.

- M2+M3 DONE — planner.go: runtime planner fires follow-up probes from discovered capabilities. Rule 1: disclosed internal hostname resolved externally -> MEDIUM pivot finding if publicly resolvable (proven by planner_test.go). Rule 2: service version -> OSV CVE-applicability probe (version-inferred, MEDIUM cap). Rules 3/4: credential/SSRF -> STOP_POLICY_BOUNDARY edges. Every decision persisted to planner-graph.jsonl (append-only, in evidence-bundle hash) + rendered as Runtime planner attack-graph section. Next: M4 adversarial ledger instrumentation.

- M1 DONE — fingerprint registry (fingerprints.json + fingerprints.go), `fp` command, wired into fingerprintService. 56 seed signatures, growable via ~/.secskills-fingerprints.json overlay. Next: M2 runtime capability planner.
