package workspace

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/gleicon/secskills/internal/netsec"
)

// ParseMixed lets flags appear before, after, or between positional args (Go's
// flag package otherwise stops at the first positional). Returns positionals.
func ParseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	return positional, nil
}

// Workdir returns the per-assessment working directory: $SECSKILLS_WORKDIR, or
// <user cache dir>/secskills/<target>. Evidence is written there, so it must be
// private: Workdir creates it 0700 and refuses a path that is a symlink, is not
// a directory, or is owned by another user, instead of writing into it.
func Workdir(target string) (string, error) {
	wd := os.Getenv("SECSKILLS_WORKDIR")
	if wd == "" {
		name := sanitize(target)
		if name == "" || name == "." || name == ".." {
			return "", fmt.Errorf("workdir: unusable target name %q", target)
		}
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("workdir: %w (set SECSKILLS_WORKDIR)", err)
		}
		wd = filepath.Join(base, "secskills", name)
	}
	if err := ensurePrivateDir(wd); err != nil {
		return "", err
	}
	return wd, nil
}

// ensurePrivateDir creates dir 0700 if missing, then verifies it is a real
// directory owned by the current user and tightens its mode to 0700.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return fmt.Errorf("workdir: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("workdir: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("workdir: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("workdir %s is not a plain directory (symlink?); refusing to write evidence there", dir)
	}
	if uid, ok := netsec.FileUID(fi); ok && uid != os.Getuid() {
		return fmt.Errorf("workdir %s is owned by uid %d, not you; refusing to write evidence there", dir, uid)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("workdir: %w", err)
		}
	}
	return nil
}

func sanitize(s string) string {
	s = strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", "*", "_").Replace(s)
	return strings.TrimPrefix(strings.TrimPrefix(s, "https___"), "http___")
}

// WriteScope records confirmed in-scope hosts so scopeCheck can gate probes.
func WriteScope(wd string, hosts []string) error {
	return os.WriteFile(filepath.Join(wd, "scope.txt"), []byte(strings.Join(hosts, "\n")+"\n"), 0o600)
}

// ScopeCheck reports whether host is within the confirmed scope for this workdir.
// A host matches if it equals or is a subdomain of a confirmed entry.
func ScopeCheck(wd, host string) bool {
	b, err := os.ReadFile(filepath.Join(wd, "scope.txt"))
	if err != nil {
		return false
	}
	host = strings.ToLower(netsec.HostOf(host))
	for _, line := range strings.Split(string(b), "\n") {
		e := strings.ToLower(strings.TrimSpace(line))
		if e == "" {
			continue
		}
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
}
