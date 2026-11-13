package exposure

import "github.com/gleicon/secskills/internal/probe"

// Short names for the embeddable probe types; the definitions live in
// internal/probe (spec N-2).
type (
	// Observation is the first non-finding output type and the v0 cache unit.
	Observation = probe.Observation
	// TLSInfo is probe.TLSInfo.
	TLSInfo = probe.TLSInfo
	// ObsStore is probe.Store.
	ObsStore = probe.Store
)
