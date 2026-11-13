package scope

import (
	"fmt"
	"os"
)

// GateNotice enforces the authorization gate in the portable core (D-5). The
// binary never sends target traffic without --confirm.
func GateNotice(mode, target string, confirmed bool) error {
	if confirmed {
		return nil
	}
	// A confirmed, unexpired engagement scope file (written by intake) authorizes
	// listed targets without a re-prompt — so a scoped engagement has nothing loose.
	if ok, why := ScopeAuthorizes(target); ok {
		fmt.Fprintf(os.Stderr, "[gate] %s\n", why)
		return nil
	}
	fmt.Fprintf(os.Stderr, `AUTHORIZATION REQUIRED — %s mode, target: %s

This sends traffic to / executes against the target. You must have written
authorization from the target owner. Re-run once authorized:

  secskills %s %s --confirm

Non-destructive by default; add --intrusive (+ --intrusive-confirm) for write/credential tests.
`, mode, target, mode, target)
	return fmt.Errorf("authorization not confirmed")
}
