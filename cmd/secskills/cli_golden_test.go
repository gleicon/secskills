package main_test

// Black-box regression suite: it builds the real binary and diffs its output
// against committed golden files. It knows nothing about the package layout,
// so it holds across refactors — any change in observable behaviour (help
// text, flags, gate refusals, report bytes, JSON shapes) fails here.
//
// Regenerate after an intended change:
//
//	go test ./cmd/secskills -run TestGolden -update
//
// Every scenario runs in its own sandbox: HOME, TMPDIR, the feed cache and the
// working directory are fresh temp dirs, the environment is whitelisted (no
// API keys leak in), and outbound HTTP is pointed at a dead proxy so no test
// can reach the network.

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var bin string

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "secskills-golden-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin = filepath.Join(dir, "secskills")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	args := []string{"build", "-o", bin}
	if os.Getenv("SECSKILLS_GOLDEN_COVER") != "" {
		// Coverage of the black-box suite: set GOCOVERDIR too, then
		// go tool covdata percent -i $GOCOVERDIR
		args = append(args, "-cover", "-coverpkg=github.com/gleicon/secskills/...")
	}
	build := exec.Command("go", append(args, ".")...)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build failed:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type sandbox struct {
	t    *testing.T
	root string // canonical (symlinks resolved)
	raw  string // as returned by TempDir
	home string
	cwd  string
	feed string
	env  []string
	out  bytes.Buffer
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	raw := t.TempDir()
	root, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := &sandbox{t: t, root: root, raw: raw,
		home: filepath.Join(root, "home"),
		cwd:  filepath.Join(root, "cwd"),
		feed: filepath.Join(root, "feed"),
	}
	tmp := filepath.Join(root, "tmp")
	binDir := filepath.Join(root, "bin")
	for _, d := range []string{s.home, s.cwd, s.feed, tmp, binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// PATH holds only a shell (evidence commands run through it), so optional
	// external tools (docker, httpx, ast-grep, whois, ...) are absent on every
	// machine and the output does not depend on what is installed.
	if err := os.Symlink("/bin/sh", filepath.Join(binDir, "sh")); err != nil {
		t.Fatal(err)
	}
	s.env = []string{
		"HOME=" + s.home,
		"USER=tester",
		"LOGNAME=tester",
		"TMPDIR=" + tmp,
		"PATH=" + binDir,
		"LANG=C",
		"TZ=UTC",
		"SECSKILLS_FEED=" + s.feed,
		"SECSKILLS_TOKEN_KEY=golden-test-key",
		"HTTP_PROXY=http://127.0.0.1:9",
		"HTTPS_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9",
		"https_proxy=http://127.0.0.1:9",
		"NO_PROXY=127.0.0.1,localhost",
	}
	if d := os.Getenv("GOCOVERDIR"); d != "" {
		s.env = append(s.env, "GOCOVERDIR="+d)
	}
	return s
}

// run executes the binary and records the command, stdout, stderr and exit
// code in the transcript.
func (s *sandbox) run(args ...string) {
	s.t.Helper()
	s.runIn(s.cwd, nil, args...)
}

func (s *sandbox) runIn(dir string, stdin []byte, args ...string) {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = s.env
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		s.t.Fatalf("run %v: %v", args, err)
	}
	if ctx.Err() != nil {
		s.t.Fatalf("run %v: timed out", args)
	}
	fmt.Fprintf(&s.out, "$ secskills %s\n", strings.Join(args, " "))
	s.out.Write(stdout.Bytes())
	if stderr.Len() > 0 {
		s.out.WriteString("[stderr]\n")
		s.out.Write(stderr.Bytes())
	}
	fmt.Fprintf(&s.out, "[exit %d]\n\n", code)
}

// cat records a file the command produced.
func (s *sandbox) cat(path string) {
	s.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(&s.out, "# file %s: %v\n\n", s.rel(path), err)
		return
	}
	fmt.Fprintf(&s.out, "# file %s\n%s\n# end\n\n", s.rel(path), b)
}

func (s *sandbox) rel(p string) string {
	return strings.Replace(strings.Replace(p, s.root, "<SANDBOX>", 1), s.raw, "<SANDBOX>", 1)
}

// copyTree copies a fixture directory into the sandbox.
func (s *sandbox) copyTree(src, dst string) {
	s.t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		s.t.Fatal(err)
	}
}

func (s *sandbox) write(path, content string) {
	s.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

type rule struct {
	re   *regexp.Regexp
	repl string
}

var normalizers = []rule{
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})`), "<TIME>"},
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?( UTC)?`), "<TIME>"},
	{regexp.MustCompile(`\b\d{8}-\d{4}-[0-9a-f]{4}\b`), "<RUNID>"},
	{regexp.MustCompile(`[0-9a-f]{64}`), "<SHA256>"},
	{regexp.MustCompile(`"latency_sec":[0-9.e+-]+`), `"latency_sec":<N>`},
	{regexp.MustCompile(`latency \d+s`), "latency <N>s"},
	{regexp.MustCompile(`\b\d{8}T\d{6}Z?\b`), "<STAMP>"},
	{regexp.MustCompile(`(127\.0\.0\.1|localhost|\[::1\]):\d+`), "$1:<PORT>"},
	{regexp.MustCompile(`\b\d+(\.\d+)?(ns|µs|us|ms)\b`), "<DUR>"},
	{regexp.MustCompile(`\b\d+\.\d+s\b`), "<DUR>"},
}

func (s *sandbox) normalized() string {
	out := s.out.String()
	if repo, err := filepath.Abs(filepath.Join("..", "..")); err == nil {
		out = strings.ReplaceAll(out, repo, "<REPO>")
	}
	out = strings.ReplaceAll(out, s.root, "<SANDBOX>")
	out = strings.ReplaceAll(out, s.raw, "<SANDBOX>")
	for _, r := range normalizers {
		out = r.re.ReplaceAllString(out, r.repl)
	}
	out = strings.ReplaceAll(out, time.Now().UTC().Format("2006-01-02"), "<TODAY>")
	return out
}

// check compares the transcript to testdata/golden/<name>.golden.
func (s *sandbox) check(name string, extra ...rule) {
	s.t.Helper()
	got := s.normalized()
	for _, r := range extra {
		got = r.re.ReplaceAllString(got, r.repl)
	}
	path := filepath.Join("testdata", "golden", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			s.t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			s.t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		s.t.Fatalf("missing golden %s (run with -update): %v", path, err)
	}
	if got != string(want) {
		s.t.Errorf("%s differs from golden:\n%s", path, diff(string(want), got))
	}
}

// diff is a minimal line diff: it reports the first divergent region.
func diff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	i := 0
	for i < len(w) && i < len(g) && w[i] == g[i] {
		i++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "first difference at line %d\n", i+1)
	for j := i; j < i+8; j++ {
		if j < len(w) {
			fmt.Fprintf(&b, "- %s\n", w[j])
		}
	}
	for j := i; j < i+8; j++ {
		if j < len(g) {
			fmt.Fprintf(&b, "+ %s\n", g[j])
		}
	}
	return b.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// commands is every top-level command main dispatches. A command added or
// dropped without updating this list (and the goldens) fails TestGoldenHelp.
var commands = []string{
	"doctor", "fetch", "post", "kb", "recipes", "source", "discover", "match",
	"leakcheck", "prefix-report", "feed", "dbcheck", "enrich", "cvematch",
	"token", "lifecycle", "kprobe", "plan", "precision", "deliver", "notify",
	"fleet", "graph", "test", "sandbox", "report", "tickets", "findings",
	"selftest", "compress", "scrub", "scan", "shodan", "profile", "scope",
	"override", "attest", "conformance", "fp", "measure", "oast-server",
	"integrity", "export", "watch", "mcp",
}

// noHelp are commands whose -h would do real work instead of printing flags.
var noHelp = map[string]bool{
	"selftest": true, "measure": true, "mcp": true, "doctor": true,
	"compress": true, "scrub": true, "scan": true, "oast-server": true,
	"conformance": false,
}

func TestGoldenHelp(t *testing.T) {
	s := newSandbox(t)
	s.run()
	s.run("help")
	s.run("version")
	s.run("no-such-command")
	for _, c := range commands {
		if noHelp[c] {
			continue
		}
		s.run(c, "-h")
	}
	s.check("help")
}

func TestGoldenKB(t *testing.T) {
	s := newSandbox(t)
	s.run("kb")
	s.run("kb", "top10")
	s.run("kb", "injection")
	s.run("kb", "no-such-class")
	s.run("recipes")
	s.run("recipes", "injection")
	s.run("fp", "list")
	s.check("kb")
}

// TestGoldenGates proves every target-touching command refuses without
// explicit authorization. These refusals are the tool's primary safety
// control; they must never silently change.
func TestGoldenGates(t *testing.T) {
	s := newSandbox(t)
	wd := filepath.Join(s.root, "wd")
	s.copyTree(filepath.Join(repoRoot(t), "testdata", "exposure", "workdir"), wd)
	s.run("discover", "example.com")
	s.run("discover", "--cidr", "203.0.113.0/24")
	s.write(filepath.Join(s.root, "tmp", "secskills-AS64500", "data", "asn-AS64500-prefixes.json"),
		`{"asn":"AS64500","prefixes":["203.0.113.0/24"],"source":"ripe-stat","fetched_at":"`+time.Now().UTC().Format(time.RFC3339)+`"}`)
	s.run("discover", "--asn", "AS64500")
	s.run("discover", "--cidr", "203.0.0.0/16", "--confirm")
	s.run("test", "example.com")
	s.run("sandbox", ".")
	s.run("integrity", "snapshot", "https://example.com")
	s.run("integrity", "verify", "https://example.com")
	s.run("leakcheck", "--workdir", wd)
	s.run("enrich", "--workdir", wd)
	s.run("dbcheck", "--workdir", wd)
	s.run("dbcheck", "--workdir", wd, "--confirm")
	s.run("kprobe", "--ip", "203.0.113.10", "--port", "22")
	s.run("watch", "example.com")
	s.check("gates")
}

func TestGoldenMatch(t *testing.T) {
	s := newSandbox(t)
	fx := filepath.Join(repoRoot(t), "testdata", "cve-2026-98432")
	s.run("match", "--fixture", fx)
	s.run("match", "--fixture", fx, "--json")
	s.check("match")
}

func TestGoldenConformance(t *testing.T) {
	s := newSandbox(t)
	s.run("conformance")
	s.run("conformance", "--json")
	s.check("conformance")
}

func TestGoldenMeasure(t *testing.T) {
	s := newSandbox(t)
	s.run("measure")
	s.cat(filepath.Join(s.cwd, "measure-report.json"))
	s.check("measure")
}

func TestGoldenSelftest(t *testing.T) {
	s := newSandbox(t)
	s.run("selftest")
	s.check("selftest")
}

func TestGoldenExposure(t *testing.T) {
	s := newSandbox(t)
	root := repoRoot(t)
	fx := filepath.Join(root, "testdata", "exposure")
	wd := filepath.Join(s.root, "wd")
	s.copyTree(filepath.Join(fx, "workdir"), wd)
	s.copyTree(filepath.Join(fx, "feed"), s.feed)
	epss, err := os.ReadFile(filepath.Join(fx, "feed", "epss.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.write(filepath.Join(s.feed, "epss-"+time.Now().UTC().Format("2006-01-02")+".json"), string(epss))
	tenants := filepath.Join(fx, "tenants.json")

	s.run("cvematch", "--workdir", wd)
	s.cat(filepath.Join(wd, "candidates.jsonl"))
	s.run("lifecycle", "reconcile", "--workdir", wd)
	s.run("lifecycle", "set", "--workdir", wd, "--ip", "203.0.113.20", "--cve", "CVE-2023-44487", "--state", "false_positive", "--note", "backport")
	s.run("lifecycle", "set", "--workdir", wd, "--ip", "203.0.113.20", "--cve", "CVE-2023-44487", "--state", "open")
	s.run("lifecycle", "reconcile", "--workdir", wd)
	s.cat(filepath.Join(wd, "findings.jsonl"))
	s.run("prefix-report", "--workdir", wd, "--label", "AS64500 203.0.113.0/24")
	s.cat(filepath.Join(wd, "exposure-report.md"))
	s.run("precision", "--workdir", wd, "--labels", filepath.Join(fx, "labels.jsonl"))
	s.run("precision", "--workdir", wd, "--labels", filepath.Join(fx, "labels.jsonl"), "--min-hosts", "1", "--min", "0.5")
	s.run("deliver", "--workdir", wd, "--tenants", tenants, "--tenant", "acme")
	s.cat(filepath.Join(wd, "feed-acme.json"))
	s.run("deliver", "--workdir", wd, "--tenants", tenants, "--tenant", "nobody")
	s.run("deliver", "--workdir", wd, "--tenants", tenants, "--tenant", "acme", "--webhook", "http://hooks.example/x")
	s.run("notify", "--workdir", wd, "--tenants", tenants, "--kev-event", "CVE-2024-6387", "--event-at", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339))
	s.cat(filepath.Join(wd, "notifications.jsonl"))
	s.run("fleet", "--workdir", wd, "--tenants", tenants, "--k", "1")
	s.run("fleet", "--workdir", wd, "--tenants", tenants)
	s.run("cvematch")
	s.run("cvematch", "--workdir", filepath.Join(s.root, "empty"))

	// plan resolves from a fresh prefix cache, so no RIPE/IRR call is made.
	planDir := filepath.Join(s.root, "plan")
	s.write(filepath.Join(planDir, "data", "asn-AS64500-prefixes.json"),
		`{"asn":"AS64500","prefixes":["203.0.113.0/24","198.51.100.0/24","192.0.2.0/25","2001:db8::/32"],"source":"ripe-stat","fetched_at":"`+
			time.Now().UTC().Format(time.RFC3339)+`"}`)
	s.run("plan", "--asn", "AS64500", "--shards", "2", "--out", planDir)
	s.cat(filepath.Join(planDir, "plan.json"))
	s.cat(filepath.Join(planDir, "shard-0.txt"))
	s.cat(filepath.Join(planDir, "shard-1.txt"))
	s.check("exposure")
}

func TestGoldenToken(t *testing.T) {
	s := newSandbox(t)
	fx := filepath.Join(repoRoot(t), "testdata", "exposure", "token.json")
	s.run("token", "sign", "--file", fx)
	// sign again into a file the verifier reads
	signed := filepath.Join(s.root, "signed.json")
	out := s.out.Len()
	s.run("token", "sign", "--file", fx)
	tr := s.out.String()[out:]
	body := tr[strings.Index(tr, "\n")+1 : strings.Index(tr, "[exit")]
	s.write(signed, body)
	s.run("token", "verify", "--file", signed)
	s.run("token", "verify", "--file", signed, "--ip", "203.0.113.17", "--class", "cve")
	s.run("token", "verify", "--file", signed, "--ip", "198.51.100.1", "--class", "cve")
	s.run("token", "verify", "--file", signed, "--ip", "203.0.113.17", "--class", "exploit")
	s.write(signed, strings.Replace(body, `"acme"`, `"evil"`, 1))
	s.run("token", "verify", "--file", signed)
	s.run("token", "verify", "--file", fx)
	s.env = append(s.env, "SECSKILLS_TOKEN_KEY=")
	s.run("token", "sign", "--file", fx)
	s.check("token")
}

func TestGoldenScope(t *testing.T) {
	s := newSandbox(t)
	s.run("scope", "--validate")
	s.run("scope", "--init")
	s.cat(filepath.Join(s.cwd, ".secskills-scope.yml"))
	s.run("scope", "--validate")
	s.check("scope")
}

// TestGoldenReporting drives the findings store end to end: add findings,
// write a run, then every renderer that reads it.
func TestGoldenReporting(t *testing.T) {
	s := newSandbox(t)
	target := "app.example.com"
	add := func(args ...string) {
		s.run(append([]string{"findings", "add", "--target", target}, args...)...)
	}
	add("--id", "FINDING-01", "--title", "Missing Content-Security-Policy header", "--host", "https://app.example.com/",
		"--severity", "MEDIUM", "--evidence-cmd", "printf 'HTTP/1.1 200 OK'", "--expected", "200 OK")
	add("--id", "FINDING-02", "--title", "Exposed .git directory", "--host", "https://app.example.com/.git/HEAD",
		"--severity", "HIGH", "--evidence-cmd", "printf 'ref: refs/heads/main'", "--expected", "ref:")
	add("--id", "FINDING-03", "--title", "SQL injection in search parameter", "--host", "https://app.example.com/search?q=",
		"--severity", "CRITICAL", "--evidence-cmd", "printf 'syntax error at or near'", "--expected", "syntax error")
	add("--id", "FINDING-04", "--title", "TLS 1.0 enabled", "--host", "app.example.com:443", "--severity", "LOW", "--status", "accepted")
	add("--id", "FINDING-05", "--title", "Server version disclosed", "--host", "https://app.example.com/", "--severity", "INFORMATIONAL")
	add("--title", "missing id")
	s.run("findings", "list", "--target", target)
	s.run("findings", "write-run", "--target", target)
	s.run("findings", "list", "--target", target)
	s.run("findings", "list", target)
	s.run("findings", "show", target)
	s.run("report", "--render", target)
	s.run("report", "--lint", target)
	s.run("report", "--audit", target)
	html := filepath.Join(s.root, "report.html")
	s.run("report", "--html", target, "--output", html)
	s.cat(html)
	s.run("tickets", target)
	s.run("tickets", "--format", "json", target)
	s.run("export", target)
	s.run("export", "--format", "cyclonedx", target)
	s.run("override", "--target", target, "--key", "nope", "--severity", "LOW", "--reason", "test")
	s.run("attest", "--sign", target)
	s.run("attest", "--verify", target)
	s.run("report", "--render", "never-assessed.example")
	s.check("reporting",
		rule{regexp.MustCompile(`("signature"|"public_key"|sig(nature)?[=:] ?)"?[A-Za-z0-9+/=]{40,}"?`), "$1<SIG>"},
	)
}

func TestGoldenMCP(t *testing.T) {
	s := newSandbox(t)
	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kb_list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"kb_get","arguments":{"class":"ssrf-xxe"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fetch","arguments":{"source":"osv","url":"http://127.0.0.1/"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"no/such","params":{}}`,
		`not json`,
	}, "\n") + "\n"
	s.runIn(s.cwd, []byte(msgs), "mcp")
	s.check("mcp")
}
