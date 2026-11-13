package workspace

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestScopeCheck(t *testing.T) {
	wd := t.TempDir()
	WriteScope(wd, []string{"example.com"})
	if !ScopeCheck(wd, "api.example.com") {
		t.Error("subdomain should be in scope")
	}
	if ScopeCheck(wd, "evil.example") {
		t.Error("foreign host must be out of scope")
	}
}

func TestWorkdirIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	t.Setenv("SECSKILLS_WORKDIR", filepath.Join(t.TempDir(), "wd"))
	fi, err := os.Stat(Workdir("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("workdir mode %o, want 700", perm)
	}
}
