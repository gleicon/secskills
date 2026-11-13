package textutil

import (
	"regexp"
	"strings"
)

// injectionRe matches common prompt-injection / jailbreak patterns. Case-insensitive.
var injectionRe = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`ignore (all |the |your )?(previous|prior|above|preceding)`,
	`disregard (all |the |your )?(previous|prior|above|instructions)`,
	`forget (all |everything|previous|your)`,
	`new instructions?`, `updated instructions?`,
	`you are (now|a |an |no longer)`, `you're (now|a |an )`,
	`system prompt`, `<\s*/?\s*system\s*>`, `\[system\]`, `\bsystem:`,
	`\bassistant:`, `\buser:`, `\bhuman:`, // fake conversation turns
	`act as`, `pretend (to be|you are)`, `roleplay`,
	`as an? (ai|llm|assistant|language model)`,
	`override (previous|your|the|all)`, `stop being`,
	`do not (tell|inform|alert|warn)`, `keep this secret`,
	`(execute|run|eval)\s+(the following|this)\s+(command|code|script)`,
	`(print|reveal|output|leak|exfiltrate)\s+(your|the)\s+(system prompt|instructions|api key|secret|token)`,
	`curl\s+https?://`, `wget\s+https?://`, // staged exfil payloads
}, "|"))

// invisible/format/bidi code points used to smuggle instructions past humans.
func isDangerousRune(r rune) bool {
	switch {
	case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF: // zero-width / BOM
		return true
	case r >= 0x202A && r <= 0x202E: // bidi embeddings/overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return true
	case r == 0x200E || r == 0x200F: // LRM / RLM
		return true
	case r == 0x00AD: // soft hyphen
		return true
	case r >= 0xE0000 && r <= 0xE007F: // unicode tag chars (invisible instruction smuggling)
		return true
	case (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7F && r <= 0x9F): // C0/C1 controls
		return true
	}
	return false
}

// stripDangerous removes invisible/bidi/control code points.
func stripDangerous(s string) string {
	return strings.Map(func(r rune) rune {
		if isDangerousRune(r) {
			return -1
		}
		return r
	}, s)
}

// DetectInjection reports whether s contains injection patterns or dangerous runes.
func DetectInjection(s string) bool {
	if injectionRe.MatchString(s) {
		return true
	}
	for _, r := range s {
		if isDangerousRune(r) {
			return true
		}
	}
	return false
}

// NeutralizeUntrusted makes a target-derived string safe to place in a finding,
// report, or stdout: strips dangerous runes, replaces injection patterns with a
// visible marker, and collapses newlines (which are used to fake system turns).
// Returns the cleaned string and whether anything was flagged.
func NeutralizeUntrusted(s string) (string, bool) {
	orig := s
	s = stripDangerous(s)
	s = injectionRe.ReplaceAllString(s, "‹redacted-injection›")
	// collapse CR/LF so a value can't fake a new conversational turn
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	flagged := s != strings.NewReplacer("\r", " ", "\n", " ").Replace(orig)
	return strings.TrimSpace(s), flagged
}

// SafeField neutralizes and length-bounds a short untrusted field (title/server).
func SafeField(s string) string {
	c, _ := NeutralizeUntrusted(s)
	if len(c) > 300 {
		c = c[:300] + "…"
	}
	return c
}
