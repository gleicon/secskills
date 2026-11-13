// Package fetch is the outbound HTTP layer: per-source throttling with backoff
// and Retry-After for free data sources, and a non-destructive client for
// target probes that refuses SSRF-unsafe destinations (see package netsec).
package fetch
