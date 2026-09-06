package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
)

// parseMixed lets flags appear before, after, or between positional args (Go's
// flag package otherwise stops at the first positional). Returns positionals.
func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
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

// workdir returns the per-assessment scratch dir ($SECSKILLS_WORKDIR or
// /tmp/secskills-<target>) and ensures it exists.
func workdir(target string) string {
	wd := os.Getenv("SECSKILLS_WORKDIR")
	if wd == "" {
		wd = filepath.Join(os.TempDir(), "secskills-"+sanitize(target))
	}
	os.MkdirAll(wd, 0o755)
	return wd
}

func sanitize(s string) string {
	s = strings.NewReplacer("/", "_", ":", "_", " ", "_", "*", "_").Replace(s)
	return strings.TrimPrefix(strings.TrimPrefix(s, "https___"), "http___")
}

// hostOf extracts the bare host from a URL/host:port.
func hostOf(target string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

// writeScope records confirmed in-scope hosts so scopeCheck can gate probes.
func writeScope(wd string, hosts []string) error {
	return os.WriteFile(filepath.Join(wd, "scope.txt"), []byte(strings.Join(hosts, "\n")+"\n"), 0o644)
}

// scopeCheck reports whether host is within the confirmed scope for this workdir.
// A host matches if it equals or is a subdomain of a confirmed entry.
func scopeCheck(wd, host string) bool {
	b, err := os.ReadFile(filepath.Join(wd, "scope.txt"))
	if err != nil {
		return false
	}
	host = strings.ToLower(hostOf(host))
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
