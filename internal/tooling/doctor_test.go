package tooling

import (
	"testing"
)

func TestParseRegistry(t *testing.T) {
	reg := ParseRegistry()
	if len(reg) < 60 {
		t.Fatalf("expected >=60 tools, got %d", len(reg))
	}
	var baseline, hasNuclei, hasTLDT bool
	for _, tool := range reg {
		if tool.Name == "curl" && tool.Tier == "skills" {
			baseline = true
		}
		if tool.Name == "nuclei" {
			hasNuclei = true
		}
		if tool.Name == "tldt" && tool.Tier == "optimizer" {
			hasTLDT = true
		}
		if len(tool.Modes) == 0 || tool.Category == "" {
			t.Errorf("tool %q missing modes/category", tool.Name)
		}
	}
	if !baseline || !hasNuclei || !hasTLDT {
		t.Errorf("registry missing expected tools: curl=%v nuclei=%v tldt=%v", baseline, hasNuclei, hasTLDT)
	}
}

func TestRenderInstall(t *testing.T) {
	cases := map[string]struct{ spec, plat, want string }{
		"go":     {"go:github.com/x/y@latest", "linux", "go install -v github.com/x/y@latest"},
		"cargo":  {"cargo:ast-grep", "linux", "cargo install ast-grep --locked"},
		"pipx":   {"pipx:sslyze", "mac", "pipx install sslyze"},
		"cask":   {"cask:docker", "mac", "brew install --cask docker"},
		"brew":   {"nmap", "mac", "brew install nmap"},
		"apt":    {"nmap", "linux", "sudo apt-get install -y nmap"},
		"script": {"script:grype", "linux", "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"},
	}
	for name, c := range cases {
		if got := RenderInstall(c.spec, c.plat); got != c.want {
			t.Errorf("%s: renderInstall(%q,%q)=%q want %q", name, c.spec, c.plat, got, c.want)
		}
	}
}

func TestModeMatch(t *testing.T) {
	if !ModeMatch("discover,test", "live") {
		t.Error("live should match discover,test")
	}
	if ModeMatch("source", "discover") {
		t.Error("source must not match discover")
	}
	if !ModeMatch("all", "source") {
		t.Error("all should match any mode")
	}
}

func TestHTTPXThreadsDefault(t *testing.T) {
	if httpxThreads(0) != "40" || httpxThreads(-1) != "40" || httpxThreads(8) != "8" {
		t.Errorf("httpxThreads: %s %s %s", httpxThreads(0), httpxThreads(-1), httpxThreads(8))
	}
}

func TestRequiredFor(t *testing.T) {
	if got := RequiredFor("sandbox"); len(got) != 1 || got[0] != "docker" {
		t.Errorf("sandbox requires %v, want [docker]", got)
	}
	for _, m := range []string{"all", "source", "discover", "test", "live"} {
		if got := RequiredFor(m); len(got) != 0 {
			t.Errorf("%s requires %v, want none", m, got)
		}
	}
	for _, tl := range ParseRegistry() {
		if tl.Tier != "skills" && tl.Tier != "power" && tl.Tier != "optimizer" {
			t.Errorf("%s has unknown tier %q", tl.Name, tl.Tier)
		}
	}
}
