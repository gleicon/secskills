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
	wd, err := Workdir("example.com")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(wd)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("workdir mode %o, want 700", perm)
	}
}

func TestWorkdirTightensExistingMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := filepath.Join(t.TempDir(), "wd")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o777)
	t.Setenv("SECSKILLS_WORKDIR", dir)
	if _, err := Workdir("x"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("existing workdir left at %o", fi.Mode().Perm())
	}
}

func TestWorkdirRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges")
	}
	base := t.TempDir()
	elsewhere := filepath.Join(base, "attacker-chosen")
	os.Mkdir(elsewhere, 0o755)
	link := filepath.Join(base, "wd")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSKILLS_WORKDIR", link)
	if _, err := Workdir("x"); err == nil {
		t.Fatal("symlinked workdir accepted")
	}
}

func TestWorkdirRefusesNonDirectory(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	t.Setenv("SECSKILLS_WORKDIR", f)
	if _, err := Workdir("x"); err == nil {
		t.Fatal("regular file accepted as workdir")
	}
}

func TestWorkdirDefaultIsPerUser(t *testing.T) {
	t.Setenv("SECSKILLS_WORKDIR", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("LocalAppData", filepath.Join(home, "AppData"))
	wd, err := Workdir("https://app.example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	cache, _ := os.UserCacheDir()
	if want := filepath.Join(cache, "secskills", "app.example.com_x"); wd != want {
		t.Errorf("workdir = %s, want %s", wd, want)
	}
	for _, bad := range []string{"..", ".", ""} {
		if _, err := Workdir(bad); err == nil {
			t.Errorf("target %q accepted", bad)
		}
	}
}

func TestWriteScopeIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	wd := t.TempDir()
	if err := WriteScope(wd, []string{"a.example"}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(wd, "scope.txt")); fi.Mode().Perm() != 0o600 {
		t.Errorf("scope.txt mode %o, want 600", fi.Mode().Perm())
	}
}
