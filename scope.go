package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// cidrContains reports whether entry is a CIDR prefix containing ip. A non-CIDR
// entry or a nil ip is never a match, so hostname and CIDR scope entries coexist
// in one targets list (spec N-1: the scope file accepts CIDR and asn: entries).
func cidrContains(entry string, ip net.IP) bool {
	if ip == nil || !strings.Contains(entry, "/") {
		return false
	}
	_, n, err := net.ParseCIDR(entry)
	return err == nil && n.Contains(ip)
}

// The engagement scope file (.secskills-scope.yml) is written by the intake
// interview and honored by the authorization gate: a target listed in an
// unexpired, confirmed scope file passes the gate without re-prompting.
//
// Minimal schema (plain key: value + "- item" lists, no YAML lib needed):
//
//   engagement: Acme external test
//   authorized: true
//   engagement_type: black-box
//   confirmed_by: jane@acme
//   expires: 2026-10-01T00:00:00Z
//   intrusive: false
//   targets:
//     - example.com
//     - api.example.com
//   out_of_scope:
//     - legacy.example.com

type scopeFile struct {
	Authorized  bool
	Intrusive   bool
	Expires     time.Time
	Targets     []string
	OutOfScope  []string
	Type        string
	ConfirmedBy string
}

func loadScopeFile(path string) (*scopeFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &scopeFile{}
	var listKey string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimRight(raw, " \r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "- ") {
			item := strings.TrimSpace(strings.TrimSpace(line)[2:])
			switch listKey {
			case "targets":
				s.Targets = append(s.Targets, strings.ToLower(item))
			case "out_of_scope":
				s.OutOfScope = append(s.OutOfScope, strings.ToLower(item))
			}
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		// strip an inline "  # comment" (space-hash), preserving '#' inside values
		if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		listKey = ""
		switch key {
		case "authorized":
			s.Authorized = val == "true" || val == "yes"
		case "intrusive":
			s.Intrusive = val == "true" || val == "yes"
		case "engagement_type":
			s.Type = val
		case "confirmed_by":
			s.ConfirmedBy = val
		case "expires":
			s.Expires, _ = time.Parse(time.RFC3339, val)
		case "targets", "out_of_scope":
			listKey = key
		}
	}
	return s, nil
}

// scopeAuthorizes reports whether an unexpired, confirmed scope file covers host.
// A scope file only authorizes when it is owned by the invoking user and not
// group/other-writable — so a scope file planted in a repo you cd into cannot
// silently authorize testing. An explicit SECSKILLS_SCOPE path is honored first.
func scopeAuthorizes(host string) (bool, string) {
	paths := []string{".secskills-scope.yml", ".secskills-scope.yaml"}
	if env := os.Getenv("SECSKILLS_SCOPE"); env != "" {
		paths = []string{env}
	}
	for _, path := range paths {
		if !scopeFileTrusted(path) {
			continue
		}
		s, err := loadScopeFile(path)
		if err != nil {
			continue
		}
		if !s.Authorized {
			return false, "scope file present but authorized: false"
		}
		if !s.Expires.IsZero() && time.Now().After(s.Expires) {
			return false, "scope file expired " + s.Expires.Format("2006-01-02")
		}
		h := strings.ToLower(hostOf(host))
		ip := net.ParseIP(h)
		for _, o := range s.OutOfScope {
			if h == o || strings.HasSuffix(h, "."+o) || cidrContains(o, ip) {
				return false, "host is explicitly out of scope"
			}
		}
		for _, t := range s.Targets {
			if h == t || strings.HasSuffix(h, "."+t) || cidrContains(t, ip) {
				return true, "authorized by " + path + " (" + s.ConfirmedBy + ")"
			}
		}
		return false, "host not listed in scope file targets"
	}
	return false, "no scope file"
}

// scopeFileTrusted requires the scope file to exist, be owned by the invoking
// user, and not be writable by group or other. A world/group-writable or
// foreign-owned file is ignored (and warned) so it cannot silently authorize.
func scopeFileTrusted(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	if fi.Mode().Perm()&0o022 != 0 {
		fmt.Fprintf(os.Stderr, "[gate] ignoring %s — group/other-writable (chmod 600)\n", path)
		return false
	}
	if uid, ok := fileUID(fi); ok && uid != os.Getuid() {
		fmt.Fprintf(os.Stderr, "[gate] ignoring %s — not owned by you\n", path)
		return false
	}
	return true
}

func cmdScope(args []string) error {
	fs := flag.NewFlagSet("scope", flag.ContinueOnError)
	initT := fs.Bool("init", false, "write a template .secskills-scope.yml")
	validate := fs.Bool("validate", false, "validate the scope file and show what it authorizes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := ".secskills-scope.yml"
	if fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	if *initT {
		if fileExists(path) {
			return fmt.Errorf("%s already exists — edit it or remove it first", path)
		}
		tmpl := `# secskills engagement scope — written by intake, honored by the authorization gate
engagement: <name>
authorized: false          # set true ONLY with written authorization from the target owner
engagement_type: black-box # black-box | grey-box | white-box
confirmed_by: <you@org>
expires: ` + time.Now().Add(720*time.Hour).Format(time.RFC3339) + `
intrusive: false           # true requires a second explicit confirmation at test time
targets:
  - <apex-domain>
out_of_scope:
  - <host-to-exclude>
`
		if err := os.WriteFile(path, []byte(tmpl), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s — edit it, set authorized: true after you have written authorization.\n", path)
		return nil
	}
	if *validate || true {
		s, err := loadScopeFile(path)
		if err != nil {
			return fmt.Errorf("cannot read %s: %w", path, err)
		}
		fmt.Printf("scope file: %s\n", path)
		fmt.Printf("  authorized: %v · type: %s · intrusive: %v\n", s.Authorized, s.Type, s.Intrusive)
		if !s.Expires.IsZero() {
			exp := "valid"
			if time.Now().After(s.Expires) {
				exp = "EXPIRED"
			}
			fmt.Printf("  expires: %s (%s)\n", s.Expires.Format(time.RFC3339), exp)
		}
		fmt.Printf("  targets: %s\n", strings.Join(s.Targets, ", "))
		if len(s.OutOfScope) > 0 {
			fmt.Printf("  out_of_scope: %s\n", strings.Join(s.OutOfScope, ", "))
		}
		if !s.Authorized {
			fmt.Println("  RESULT: NOT authorized — discover/test will require --confirm until authorized: true.")
		} else {
			fmt.Println("  RESULT: authorized — listed targets pass the gate without --confirm.")
		}
	}
	return nil
}
