package report

import (
	"strings"

	"github.com/gleicon/secskills/internal/finding"
)

// PriorityFor maps a severity to a ticket priority (CRITICAL=P1 … INFORMATIONAL=P5).
func PriorityFor(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "P1"
	case "HIGH":
		return "P2"
	case "MEDIUM":
		return "P3"
	case "LOW":
		return "P4"
	default:
		return "P5"
	}
}

// DedupeByKey collapses findings that share a stable finding_key (e.g. TLS 1.0 +
// TLS 1.1 on the same host both key to that host's tls-config) into one ticket,
// keeping the highest severity. Prevents three tickets for one edge config.
func DedupeByKey(fs []finding.Finding) []finding.Finding {

	best := map[string]int{} // key -> index into out
	var out []finding.Finding
	for i := range fs {
		f := fs[i]
		k := f.Key
		if k == "" {
			k = finding.ObservationKey(&f)
		}
		if j, ok := best[k]; ok {
			if finding.SeverityOrder[f.Severity] < finding.SeverityOrder[out[j].Severity] {
				out[j] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	return out
}
