package main

import (
	"testing"
	"time"
)

func TestParseRegistry(t *testing.T) {
	reg := parseRegistry()
	if len(reg) < 60 {
		t.Fatalf("expected >=60 tools, got %d", len(reg))
	}
	var baseline, hasNuclei, hasTLDT bool
	for _, tool := range reg {
		if tool.Name == "curl" && tool.Tier == "baseline" {
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
		if got := renderInstall(c.spec, c.plat); got != c.want {
			t.Errorf("%s: renderInstall(%q,%q)=%q want %q", name, c.spec, c.plat, got, c.want)
		}
	}
}

func TestModeMatch(t *testing.T) {
	if !modeMatch("discover,test", "live") {
		t.Error("live should match discover,test")
	}
	if modeMatch("source", "discover") {
		t.Error("source must not match discover")
	}
	if !modeMatch("all", "source") {
		t.Error("all should match any mode")
	}
}

func TestSourceInterval(t *testing.T) {
	if sourceInterval("crtsh") != 2*time.Second {
		t.Error("crtsh interval should be 2s")
	}
	if sourceInterval("osv") != 200*time.Millisecond {
		t.Error("osv interval should be 200ms")
	}
	if sourceInterval("unknown") != time.Second {
		t.Error("default interval should be 1s")
	}
}

func TestSelftest(t *testing.T) {
	if err := cmdSelftest(nil); err != nil {
		t.Fatalf("end-to-end selftest failed: %v", err)
	}
}

func TestScopeCheck(t *testing.T) {
	wd := t.TempDir()
	writeScope(wd, []string{"example.com"})
	if !scopeCheck(wd, "api.example.com") {
		t.Error("subdomain should be in scope")
	}
	if scopeCheck(wd, "evil.com") {
		t.Error("foreign host must be out of scope")
	}
}

func TestKBClasses(t *testing.T) {
	classes := kbClasses()
	if len(classes) < 9 {
		t.Fatalf("expected >=9 KB classes, got %d", len(classes))
	}
	if !contains(classes, "injection") || !contains(classes, "top10") {
		t.Error("KB missing injection/top10 classes")
	}
	if _, err := kbClassText("injection"); err != nil {
		t.Errorf("kbClassText(injection): %v", err)
	}
}
