package main

import "github.com/gleicon/secskills/internal/probe"

// The CLI re-exports the embeddable probe types so call sites use the short
// names while the definitions live in internal/probe (spec N-2). Detectors move
// into the package class by class; these aliases keep every existing call site
// compiling in the meantime, with zero behavioral change.
type (
	// Observation is the first non-finding output type and the v0 cache unit.
	Observation = probe.Observation
	TLSInfo     = probe.TLSInfo
	ObsStore    = probe.Store
)
