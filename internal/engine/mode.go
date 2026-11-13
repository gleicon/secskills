package engine

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/tooling"
)

// ---- discover ----------------------------------------------------------------

// ---- test --------------------------------------------------------------------

// RunAdversarialStage is the adversarial-readonly module list for one host.
// It lives outside the test closure so per-host orchestration stays scannable as
// modules are added. Modules that issue their own request sequence (the LLM
// probes) take the rate gate and charge one tick per request; single-pass
// modules take one tick here.
func RunAdversarialStage(wd, u string, lh tooling.LiveHost, oast *OAST, tick *time.Ticker) []finding.Finding {
	var fnd []finding.Finding
	<-tick.C
	fnd = append(fnd, runAdversarial(wd, u, oast)...)
	if f := llmWarmupProbe(wd, u, tick.C); f != nil {
		fnd = append(fnd, *f)
	}
	fnd = append(fnd, llmChatbotProbe(wd, u, oast, tick.C)...)
	if lh.Status == 401 || lh.Status == 403 {
		<-tick.C
		if f := bypassProbe(wd, u, lh.Status); f != nil {
			fnd = append(fnd, *f)
		}
		<-tick.C
		if f := trustedHeaderBypass(wd, u, lh.Status); f != nil {
			fnd = append(fnd, *f)
		}
	}
	return fnd
}

// ---- sandbox -----------------------------------------------------------------

// ---- helpers -----------------------------------------------------------------

// ModeLabel names the run mode for output.
func ModeLabel(intrusive bool) string {
	if intrusive {
		return "INTRUSIVE"
	}
	return "non-destructive"
}

// NormalizeURL defaults a bare host to https://.
func NormalizeURL(t string) string {
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return t
	}
	return "https://" + t
}

// WriteArtifactLines writes lines to <wd>/<name>, one per line.
func WriteArtifactLines(wd, name string, lines []string) {
	os.WriteFile(filepath.Join(wd, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
