package main

import (
	"strings"
	"testing"
)

func TestClassifyHTTPLeakVCS(t *testing.T) {
	cfg := "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
	leak, ev := classifyHTTPLeak("exposed-vcs", 200, "text/plain", cfg)
	if !leak || ev == "" {
		t.Fatalf("served .git/config must be flagged: %v %q", leak, ev)
	}
	// A 404 or an HTML page is not a leak.
	if leak, _ := classifyHTTPLeak("exposed-vcs", 404, "text/html", "<html>nope</html>"); leak {
		t.Error("404 must not be a leak")
	}
	if leak, _ := classifyHTTPLeak("exposed-vcs", 200, "text/html", "<html>app</html>"); leak {
		t.Error("an HTML page at /.git/config is not a git config")
	}
}

func TestClassifyDotenvRedactsValues(t *testing.T) {
	env := "DB_PASSWORD=sup3rs3cret\nAPI_KEY=abcd1234\nDEBUG=true\n"
	leak, ev := classifyHTTPLeak("exposed-dotenv", 200, "text/plain", env)
	if !leak {
		t.Fatal("served .env must be flagged")
	}
	for _, secret := range []string{"sup3rs3cret", "abcd1234"} {
		if strings.Contains(ev, secret) {
			t.Fatalf("evidence must redact secret values, leaked %q in %q", secret, ev)
		}
	}
	for _, key := range []string{"DB_PASSWORD", "API_KEY"} {
		if !strings.Contains(ev, key) {
			t.Errorf("evidence should name key %q", key)
		}
	}
}

func TestLooksLikeDotenvRejectsHTML(t *testing.T) {
	if looksLikeDotenv("<!doctype html><html><body>404</body></html>") {
		t.Error("HTML must not be classified as a dotenv")
	}
	if !looksLikeDotenv("A=1\nB=2\n") {
		t.Error("real env shape must pass")
	}
}

func TestDirListing(t *testing.T) {
	if !dirListing("<h1>Index of /</h1>") {
		t.Error("apache index must be detected")
	}
	if dirListing("<html>welcome</html>") {
		t.Error("ordinary page is not a listing")
	}
}
