package textutil

import (
	crand "crypto/rand"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ReSecretish matches a credential-like key followed by a separator. Detectors
// use it as a heuristic; RedactedSample uses it to mask values.
var ReSecretish = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|token|bearer|authorization)\s*[=:"']`)

// RandToken returns a random 12-hex-char marker for probe payloads.
func RandToken() string {
	b := make([]byte, 6)
	crand.Read(b)
	return fmt.Sprintf("%x", b)
}

// OrNone returns "(none)" for an empty string.
func OrNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}

// RedactedSample returns up to n non-empty lines of a response body, with
// credential-like values redacted, prefixed as observed evidence.
func RedactedSample(body string, n int) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = redactSecrets(line)
		if len(line) > 160 {
			line = line[:160] + "…"
		}
		out = append(out, "  "+line)
		if len(out) >= n {
			break
		}
	}
	if len(out) == 0 {
		return "  (no sample lines)"
	}
	return "sample:\n" + strings.Join(out, "\n")
}

var bearerToken = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+`)

// redactSecrets masks the value after the first credential-like key, through
// the end of the line (the value may be quoted, spaced, or followed by more
// secrets), and any bare "Bearer <token>".
func redactSecrets(line string) string {
	if loc := ReSecretish.FindStringSubmatchIndex(line); loc != nil {
		line = line[:loc[0]] + line[loc[2]:loc[3]] + "=[REDACTED]"
	}
	return bearerToken.ReplaceAllString(line, "Bearer [REDACTED]")
}

// Contains reports whether v is in s.
func Contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// OrNA returns "not recorded" for an empty string, else s trimmed of a trailing ";".
func OrNA(s string) string {
	if strings.TrimSpace(s) == "" {
		return "not recorded"
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ";"))
}

// FileExists reports whether p can be stat-ed.
func FileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// IPRe matches an IPv4 address, capturing its first three octets.
var IPRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b`)

// ReadLines returns the trimmed non-empty lines of a file, or nil.
func ReadLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// Dash returns an em dash for an empty string.
func Dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// OrDash is Dash.
func OrDash(s string) string { return Dash(s) }

// ReadFileOr returns the file contents, or def when it cannot be read.
func ReadFileOr(p, def string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return def
	}
	return string(b)
}

// Ratio returns a/b, or 1 when b is 0 (an empty set is a perfect score).
func Ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

// FirstLine returns s up to its first newline.
func FirstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Itoa formats n in base 10.
func Itoa(n int) string { return strconv.Itoa(n) }
