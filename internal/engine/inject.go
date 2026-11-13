package engine

import (
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
)

// This file is the prompt-injection defense. secskills runs inside an LLM-enabled
// environment (Claude Code, opencode, MCP). Everything collected from a target —
// page titles, server headers, DNS names, Shodan output, nuclei names, response
// bodies — is UNTRUSTED and may contain text engineered to hijack the reading
// model ("ignore previous instructions", fake system turns, tool-call bait,
// invisible/bidi unicode). No target-derived string reaches a finding, a report,
// or stdout without passing through neutralizeUntrusted first.

// ScanArtifactForInjection scans a saved artifact file; if it contains injection
// patterns it returns a MEDIUM finding (CWE-77) recording the attempt. tldt is
// used as an additional detection layer when present.
func ScanArtifactForInjection(path, sourceLabel string) *finding.Finding {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	native := textutil.DetectInjection(string(b))
	tldtHit := tldtDetect(path)
	if !native && !tldtHit {
		return nil
	}
	layer := "native"
	if tldtHit {
		layer += "+tldt"
	}
	f := &finding.Finding{
		Title:     "Prompt-injection content in target output (" + sourceLabel + ")",
		Host:      sourceLabel,
		Severity:  "MEDIUM",
		Status:    "open",
		CWE:       "CWE-77",
		OWASP:     "A03:2021 Injection",
		KBClass:   "injection",
		ProbeKind: "manual",
	}
	f.References = []string{"detected by: " + layer, "content neutralized before analysis"}
	return f
}

// tldtDetect runs `tldt --detect-injection --detect-only` on a file as a second
// detection layer. Best-effort: returns false if tldt is absent or errors.
func tldtDetect(path string) bool {
	if _, err := exec.LookPath("tldt"); err != nil {
		return false
	}
	out, err := tooling.RunCmdTimeout(20*time.Second, "tldt", "-f", path, "--detect-injection", "--detect-only", "--format", "json")
	if err != nil {
		return false
	}
	s := strings.ToLower(string(out))
	return strings.Contains(s, `"flagged":true`) || strings.Contains(s, `"kind":"injection"`)
}
