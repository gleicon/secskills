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
- [ ] M2 — Runtime capability planner (stateful chaining: discover cap → decide → new probe → new evidence)
- [ ] M3 — Persisted attack-graph edges (cap → decision → probe → evidence objects)
- [ ] M4 — Adversarial ledger real instrumentation (per-probe counters, not derived)
- [ ] M5 — Second-stage depth (per-service version→CVE applicability + auth-boundary)
- [ ] M6 — Engine self-measurement corpus (deliberately vuln + secure targets; FP rate, precision/recall, validation-success, avg depth) + fixtures for adversarial/edge/second-stage detectors
- [ ] M7 — Self-hostable OAST collaborator (`secskills oast-server`) + wire SSRF/XXE validation
- [ ] M8 — Origin looking-glass depth (JARM fingerprint; Censys / passive-DNS adapters, key-gated)
- [ ] M9 — Interop exports (SARIF + CycloneDX/VEX)
- [ ] M10 — Continuous mode (`secskills watch`: scheduled retest + posture drift)
- [ ] M11 — Per-evidence signing (evidence manifest hash-chain + signature)
- [ ] M12 — Credentialed depth (authorized-exploit: BOLA/IDOR user-A-vs-B, session/JWT/cookie, OAuth flow)

## Status log
(append newest at top)

- M1 DONE — fingerprint registry (fingerprints.json + fingerprints.go), `fp` command, wired into fingerprintService. 56 seed signatures, growable via ~/.secskills-fingerprints.json overlay. Next: M2 runtime capability planner.
