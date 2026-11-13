package finding

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Finding mirrors the redteam-pentest findings-store schema (D-4).
type Finding struct {
	ID            string              `json:"id"`
	Title         string              `json:"title"`
	Host          string              `json:"host"`
	Severity      string              `json:"severity"`
	Status        string              `json:"status"` // open|mitigated|regressed|accepted|manual
	EvidenceCmd   string              `json:"evidence_cmd"`
	ExpectedOpen  string              `json:"expected_open_pattern"`
	LastResponse  string              `json:"last_response,omitempty"`
	ResponseHash  string              `json:"response_hash"`
	FirstSeenRun  string              `json:"first_seen_run"`
	LastTestedRun string              `json:"last_tested_run"`
	RetestHistory []map[string]string `json:"retest_history"`
	// Framework mapping (OWASP / CWE / cheatsheet / CVE) — filled by classify().
	OWASP      string   `json:"owasp,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
	KBClass    string   `json:"kb_class,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	References []string `json:"references,omitempty"`
	// Structured probe — how retest re-verifies the finding in Go, with no shell.
	// ProbeKind: header-missing | tls-weak | body-contains | status | manual.
	// Response-integrity baselines are verified by `secskills integrity verify`,
	// not by retest (a POST chat surface cannot be re-fetched with a GET).
	ProbeKind string `json:"probe_kind,omitempty"`
	ProbeURL  string `json:"probe_url,omitempty"`
	ProbeArg  string `json:"probe_arg,omitempty"`
	// Evidence/risk model (separate confidence from severity).
	// Confidence: Confirmed | High | Medium | Low.
	// Validation: exploited | behavior-confirmed | version-inferred | config-inferred | passive.
	Confidence string `json:"confidence,omitempty"`
	Validation string `json:"validation,omitempty"`
	// ImpactText is asset-specific, replacing the generic per-class string when set.
	ImpactText string `json:"impact,omitempty"`
	// ObservedEvidence is what the test actually observed (facts), distinct from
	// EvidenceCmd which is only a reproduction command.
	ObservedEvidence string `json:"observed_evidence,omitempty"`
	// Provenance: how this asset/finding was discovered and whether it is in scope.
	DiscoveredFrom string `json:"discovered_from,omitempty"`
	// Audit identity: DetectorID names the detector; Key is a stable hash so a
	// finding persists across runs (open→mitigated→regressed) independent of F-NNN.
	DetectorID string `json:"detector_id,omitempty"`
	Key        string `json:"finding_key,omitempty"`      // observation identity (asset+detector+condition)
	RootKey    string `json:"root_finding_key,omitempty"` // collapse identity (asset+detector family)
	// Formal evidence state (state machine) + immutable evidence object ids.
	State        string   `json:"evidence_state,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	// Severity provenance: automated (rubric) severity is immutable; a human
	// adjudication is recorded separately, never by mutating Severity.
	AutomatedSeverity string    `json:"automated_severity,omitempty"`
	Override          *Override `json:"override,omitempty"`
	// HIGH-invariant support: when a nominal HIGH lacks a validated exploit
	// primitive, severity is capped and the escalation condition is recorded.
	PotentialSeverity   string `json:"potential_severity,omitempty"`
	EscalationCondition string `json:"escalation_condition,omitempty"`
	// per-observation time (audit forensics): exact capture time of the evidence.
	ObservedAt  string `json:"observed_at,omitempty"`
	FirstSeen   string `json:"first_seen,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
	FixedAt     string `json:"fixed_at,omitempty"`
	RegressedAt string `json:"regressed_at,omitempty"`
	// Adversarial model: capabilities this finding grants an attacker (drives the
	// attack graph), and any pivot intelligence extracted from it.
	Capabilities []string `json:"capabilities,omitempty"`
	Pivots       []string `json:"pivots,omitempty"`
}

// Run is one stored assessment run.
type Run struct {
	RunID         string         `json:"run_id"`
	Target        string         `json:"target"`
	Date          string         `json:"date"`
	Type          string         `json:"type"`
	PreviousRunID string         `json:"previous_run_id,omitempty"`
	FindingCounts map[string]int `json:"finding_counts"`
	StatusCounts  map[string]int `json:"status_counts,omitempty"`
	Findings      []Finding      `json:"findings"`
}

// NowRFC returns the current UTC time in RFC 3339.
func NowRFC() string { return time.Now().UTC().Format(time.RFC3339) }

// StoreDir is the findings store for target (~/.secskills-findings/<target>).
func StoreDir(target string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secskills-findings", target)
}

// RunID returns a new run id: UTC minute plus a short hash.
func RunID(target string, count int) string {
	h := sha256.Sum256([]byte(target + time.Now().UTC().Format(time.RFC3339) + fmt.Sprint(count)))
	return time.Now().UTC().Format("20060102-1504") + "-" + fmt.Sprintf("%x", h[:2])
}

// SeverityOrder ranks severities most-severe first; shared by every sort/collapse.
var SeverityOrder = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}

// SortFindings orders findings by severity, most severe first (stable).
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return SeverityOrder[fs[i].Severity] < SeverityOrder[fs[j].Severity] })
}
