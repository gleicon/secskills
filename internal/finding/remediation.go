package finding

import (
	"github.com/gleicon/secskills/internal/scope"
)

func impactFor(kb string) string {
	switch kb {
	case "config-exposure":
		return "Missing hardening or exposed operational endpoints disclose internal state and enable clickjacking, MIME-sniffing, or cross-origin abuse; exposed metrics/config can leak topology, versions, and secrets."
	case "crypto-secrets":
		return "Deprecated TLS and missing HSTS enable downgrade/MITM and session interception on hostile networks."
	case "components-supply-chain":
		return "Known-vulnerable component versions expose the host to publicly documented exploits (see linked CVEs)."
	case "access-control":
		return "Broken access control lets a user act outside intended permissions — reading or modifying other tenants' data or reaching privileged functions."
	case "auth-session":
		return "Authentication/session weaknesses enable account takeover via brute force, fixation, or token abuse."
	case "injection":
		return "Untrusted input reaching an interpreter enables data theft, code execution, or client-side compromise."
	case "ssrf-xxe":
		return "Server-side request forgery / XXE can reach internal services and cloud metadata, enabling pivot and credential theft."
	case "llm-agents":
		return "Prompt injection and unsafe output handling let an attacker steer the model/agent, exfiltrate context, or reach downstream sinks and tools."
	case "mobile":
		return "Mobile weaknesses expose credentials, PII, and traffic on-device or in transit, and widen the backend attack surface."
	default:
		return "See the referenced cheat sheet for impact and remediation."
	}
}

func remediationFor(kb string) string {
	switch kb {
	case "config-exposure":
		return "Set the full security-header set at the edge; authenticate or firewall operational endpoints."
	case "crypto-secrets":
		return "Enforce TLS 1.2+/1.3, HSTS with a long max-age, and Secure/HttpOnly/SameSite cookies."
	case "components-supply-chain":
		return "Upgrade to a fixed version, hide version banners, and add dependency scanning."
	default:
		return "Apply the control from the referenced cheat sheet."
	}
}

// ScopeAuthLine reports the authorization basis for the target, read from the
// scope file if one authorizes it, else a neutral statement.
func ScopeAuthLine(target string) string {
	if ok, why := scope.ScopeAuthorizes(target); ok {
		return "Confirmed — " + why
	}
	return "Operator attestation: `--confirm` supplied. Written authorization is an engagement prerequisite and is **not** validated or stored by the assessment engine."
}
