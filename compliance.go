package main

import "strings"

// complianceMap returns the SOC 2, ISO 27001, and PCI-DSS controls a finding maps
// to, so the report doubles as compliance evidence (CISO can attach it to a SOC 2
// audit). Keyed by KB class / OWASP category.
type compliance struct {
	SOC2 string
	ISO  string
	PCI  string
	Team string // suggested owning team, for splitting work across groups
}

func complianceFor(kbClass string) compliance {
	switch kbClass {
	case "config-exposure":
		return compliance{
			SOC2: "CC6.1 (logical access), CC6.6 (perimeter), CC7.2 (monitoring)",
			ISO:  "A.8.20 network security, A.8.9 config management",
			PCI:  "1.2/1.3 (network), 2.2 (secure config), 6.4.1",
			Team: "Platform / Edge / SRE",
		}
	case "crypto-secrets":
		return compliance{
			SOC2: "CC6.1, CC6.7 (transmission of data)",
			ISO:  "A.8.24 cryptography, A.5.33 protection of records",
			PCI:  "4.1/4.2 (strong cryptography in transit)",
			Team: "Platform / Edge",
		}
	case "components-supply-chain":
		return compliance{
			SOC2: "CC7.1 (vuln management), CC8.1 (change management)",
			ISO:  "A.8.8 technical vulnerabilities, A.8.19 software on systems",
			PCI:  "6.3.1/6.3.2 (patching, inventory), 11.3",
			Team: "AppSec / Platform / Dependency owners",
		}
	case "access-control":
		return compliance{
			SOC2: "CC6.1, CC6.2 (registration/authorization), CC6.3 (least privilege)",
			ISO:  "A.5.15 access control, A.8.3 information access restriction",
			PCI:  "7.1/7.2 (need-to-know access)",
			Team: "AppSec / Application teams",
		}
	case "auth-session":
		return compliance{
			SOC2: "CC6.1, CC6.2, CC6.3",
			ISO:  "A.5.17 authentication information, A.8.5 secure authentication",
			PCI:  "8.2/8.3 (authentication, MFA)",
			Team: "IAM / AppSec",
		}
	case "injection":
		return compliance{
			SOC2: "CC7.1, CC8.1 (secure SDLC)",
			ISO:  "A.8.28 secure coding, A.8.26 application security requirements",
			PCI:  "6.2.4 (injection defenses), 6.3",
			Team: "Application teams / AppSec",
		}
	case "ssrf-xxe":
		return compliance{
			SOC2: "CC6.1, CC7.1",
			ISO:  "A.8.28 secure coding, A.8.20 network security",
			PCI:  "6.2.4",
			Team: "Application teams / AppSec",
		}
	case "logging-monitoring":
		return compliance{
			SOC2: "CC7.2 (monitoring), CC7.3 (evaluation), CC7.4 (incident response)",
			ISO:  "A.8.15 logging, A.8.16 monitoring activities",
			PCI:  "10.2/10.3 (audit logs)",
			Team: "SecOps / SOC",
		}
	case "mobile":
		return compliance{
			SOC2: "CC6.1, CC6.7, CC7.1",
			ISO:  "A.8.28 secure coding, A.8.24 cryptography",
			PCI:  "6.2, 4.1",
			Team: "Mobile team / AppSec",
		}
	case "llm-agents":
		return compliance{
			SOC2: "CC6.1, CC7.1, CC8.1",
			ISO:  "A.8.28 secure coding, A.5.23 cloud services security",
			PCI:  "6.2 (secure development)",
			Team: "AI/ML team / AppSec",
		}
	default:
		return compliance{
			SOC2: "CC6.1, CC7.1",
			ISO:  "A.8.8, A.8.28",
			PCI:  "6.2/6.3",
			Team: "AppSec",
		}
	}
}

// cvssBand maps a severity to an indicative CVSS v3.1 base-score band (the tool
// does not compute per-finding vectors; the band communicates order of magnitude).
func cvssBand(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "9.0–10.0"
	case "HIGH":
		return "7.0–8.9"
	case "MEDIUM":
		return "4.0–6.9"
	case "LOW":
		return "0.1–3.9"
	default:
		return "0.0 (informational)"
	}
}
