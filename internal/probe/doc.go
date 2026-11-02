// Package probe is the embeddable detection core extracted from the secskills
// CLI (spec N-2). It turns a target plus a budget into observations and
// findings as data, so an orchestrator can run detections across an ASN without
// spawning a process per asset.
//
// The package has no import of package main: every host-specific dependency
// (the SSRF guard, the user-agent string, the rate gate) is injected. That
// keeps the safety properties decided in one place while letting both the CLI
// (Mode A) and a token-scoped worker (Mode B) share one request path.
//
// Observation is the first non-finding output type and the v0 cache unit. It is
// append-only, sourced, timestamped, and content-addressed from day one, so the
// stored corpus can later back vector search ("Google for vuln") without a
// rewrite. The scan is throwaway; the store is the asset.
package probe
