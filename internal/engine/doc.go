// Package engine is the assessment engine behind discover and test: surface
// discovery, OWASP-mapped checks and detector packs, the adversarial planner,
// edge/CDN mapping, deep scans, and the local conformance/measure corpora.
//
// Every target-touching entry point assumes the caller has passed the
// authorization gate (package scope) and goes through the guarded HTTP layer
// (package fetch).
package engine
