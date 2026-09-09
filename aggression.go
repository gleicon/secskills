package main

import (
	"os"
	"path/filepath"
	"strings"
)

// Aggression profile defines how adversarial the engine may be. Each level is a
// strict superset of the one below. This appears in the report + attestation so
// an auditor understands why some validation occurred while destructive impact
// was intentionally stopped.
type Profile int

const (
	ProfilePassive           Profile = iota // OSINT only, no target traffic beyond discovery
	ProfileSafeActive                       // header/TLS/exposure checks (the classic scanner)
	ProfileAdversarialRO                    // + bypass variants, safe exploit primitives, OAST, stateful pivots
	ProfileAuthorizedExploit                // + credentialed/state-changing (requires --intrusive)
)

func parseProfile(s string) Profile {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "passive":
		return ProfilePassive
	case "safe-active", "safe", "":
		return ProfileSafeActive
	case "adversarial-readonly", "adversarial-ro", "adversarial":
		return ProfileAdversarialRO
	case "authorized-exploit", "exploit":
		return ProfileAuthorizedExploit
	}
	return ProfileSafeActive
}

func (p Profile) String() string {
	switch p {
	case ProfilePassive:
		return "passive"
	case ProfileSafeActive:
		return "safe-active"
	case ProfileAdversarialRO:
		return "adversarial-readonly"
	case ProfileAuthorizedExploit:
		return "authorized-exploit"
	}
	return "safe-active"
}

// adversarial reports whether the profile permits read-only adversarial behavior
// (bypass variants, safe exploit primitives, OAST callbacks, stateful pivots).
func (p Profile) adversarial() bool { return p >= ProfileAdversarialRO }

// profileDescription is rendered into the report methodology + attestation.
func profileDescription(p Profile) string {
	switch p {
	case ProfilePassive:
		return "Passive: OSINT and public data only; no active probing of the target."
	case ProfileSafeActive:
		return "Safe-active: unauthenticated header/TLS/exposure checks and discovery. No exploit attempts."
	case ProfileAdversarialRO:
		return "Adversarial-readonly: aggressive enumeration, request-variant authorization-bypass testing, harmless exploit primitives (open-redirect, SSTI arithmetic, path-traversal markers, OAST-validated SSRF), object-storage enumeration, and stateful follow-up pivots. **No state changes, no credential attacks, no denial of service.** Validation stops at a defined proof boundary (prove the primitive, not maximum impact)."
	case ProfileAuthorizedExploit:
		return "Authorized-exploit: adversarial-readonly plus credentialed and state-changing tests. Requires explicit --intrusive authorization."
	}
	return ""
}

// readProfile loads the aggression profile recorded for a run (default safe-active).
func readProfile(wd string) Profile {
	b, err := os.ReadFile(filepath.Join(wd, "profile.txt"))
	if err != nil {
		return ProfileSafeActive
	}
	return parseProfile(strings.TrimSpace(string(b)))
}
