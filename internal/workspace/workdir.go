package workspace

import (
	"flag"
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

// Workdir returns the per-assessment scratch dir ($SECSKILLS_WORKDIR or
// /tmp/secskills-<target>) and ensures it exists.
func Workdir(target string) string {
	wd := os.Getenv("SECSKILLS_WORKDIR")
	if wd == "" {
		wd = filepath.Join(os.TempDir(), "secskills-"+sanitize(target))
	}
	os.MkdirAll(wd, 0o700) // evidence lives here: owner-only
	return wd
}

func sanitize(s string) string {
	s = strings.NewReplacer("/", "_", ":", "_", " ", "_", "*", "_").Replace(s)
	return strings.TrimPrefix(strings.TrimPrefix(s, "https___"), "http___")
}

// WriteScope records confirmed in-scope hosts so scopeCheck can gate probes.
func WriteScope(wd string, hosts []string) error {
	return os.WriteFile(filepath.Join(wd, "scope.txt"), []byte(strings.Join(hosts, "\n")+"\n"), 0o644)
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
