package workspace

import (
	"testing"
)

func TestScopeCheck(t *testing.T) {
	wd := t.TempDir()
	WriteScope(wd, []string{"example.com"})
	if !ScopeCheck(wd, "api.example.com") {
		t.Error("subdomain should be in scope")
	}
	if ScopeCheck(wd, "evil.com") {
		t.Error("foreign host must be out of scope")
	}
}
