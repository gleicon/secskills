package tooling

import (
	"runtime"
	"strings"

	"github.com/gleicon/secskills"
)

// Tool is one row of the embedded registry (tools/registry.tsv).
type Tool struct {
	Name     string `json:"tool"`
	Tier     string `json:"tier"`     // baseline | power | optimizer
	Category string `json:"category"` // core, osint, dns, http, ...
	Modes    string `json:"modes"`    // csv: discover,test,source,...
	Mac      string `json:"-"`
	Linux    string `json:"-"`
	Note     string `json:"note"`
	Status   string `json:"status"`  // present | absent (filled by check)
	Install  string `json:"install"` // platform-resolved command
}

// ParseRegistry parses the tab-separated tool registry.
func ParseRegistry() []Tool {
	var out []Tool
	for _, line := range strings.Split(strings.TrimSpace(secskills.ToolRegistry), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		out = append(out, Tool{
			Name: f[0], Tier: f[1], Category: f[2], Modes: f[3],
			Mac: f[4], Linux: f[5], Note: f[6],
		})
	}
	return out
}

// Platform names the install-command column for this OS (mac, linux, …).
func Platform() string {
	switch runtime.GOOS {
	case "darwin":
		return "mac"
	case "linux":
		return "linux"
	default:
		return "other"
	}
}

// RenderInstall turns a registry install spec into a runnable command for the
// current platform, mirroring tools/doctor.sh render_install.
func RenderInstall(spec, plat string) string {
	switch {
	case strings.HasPrefix(spec, "go:"):
		return "go install -v " + strings.TrimPrefix(spec, "go:")
	case strings.HasPrefix(spec, "cargo:"):
		return "cargo install " + strings.TrimPrefix(spec, "cargo:") + " --locked"
	case strings.HasPrefix(spec, "pipx:"):
		return "pipx install " + strings.TrimPrefix(spec, "pipx:")
	case strings.HasPrefix(spec, "npm:"):
		return "npm install -g " + strings.TrimPrefix(spec, "npm:")
	case strings.HasPrefix(spec, "cask:"):
		return "brew install --cask " + strings.TrimPrefix(spec, "cask:")
	case strings.HasPrefix(spec, "git:"):
		return "git clone " + strings.TrimPrefix(spec, "git:")
	case spec == "script:trivy":
		return "curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
	case spec == "script:grype":
		return "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
	case spec == "script:syft":
		return "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
	case spec == "script:trufflehog":
		return "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
	default:
		if plat == "mac" {
			return "brew install " + spec
		}
		return "sudo apt-get install -y " + spec
	}
}

// ModeMatch reports whether a tool's comma-separated modes include req.
func ModeMatch(toolModes, req string) bool {
	if req == "all" {
		return true
	}
	m := "," + toolModes + ","
	if strings.Contains(m, ",all,") {
		return true
	}
	if req == "live" {
		return strings.Contains(m, ",discover,") || strings.Contains(m, ",test,") || strings.Contains(m, ",live,")
	}
	return strings.Contains(m, ","+req+",")
}
