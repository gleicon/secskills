package tooling

import (
	"os/exec"

	"github.com/gleicon/secskills/internal/textutil"
)

// ChromePath finds a headless Chrome/Chromium binary, or returns "".
func ChromePath() string {
	for _, b := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	if p := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; textutil.FileExists(p) {
		return p
	}
	return ""
}
