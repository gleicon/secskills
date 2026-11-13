package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/gleicon/secskills/internal/engine"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/kb"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/report"
	"github.com/gleicon/secskills/internal/textutil"
	"github.com/gleicon/secskills/internal/tooling"
	"github.com/gleicon/secskills/internal/workspace"
)

// cmdSelftest runs the pipeline end-to-end against a local, disposable server we
// spin up ourselves — authorized by construction, no third party touched. It
// exercises the check engine, findings store, run persistence, and report
// render, then asserts the expected findings appeared. This is the automatable
// stand-in for a live engagement.
func cmdSelftest(_ []string) error {
	// A deliberately weak server: no security headers, an exposed /metrics.
	mux := http.NewServeMux()
	// realistic: root serves the app, unknown paths 404 (not catch-all)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "<html><title>weak app</title>ok</html>")
	})
	// genuinely exposed metrics with a real Prometheus signature
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "# HELP process_cpu_seconds_total Total user and system CPU time.\nprocess_cpu_seconds_total 1.0")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	url := srv.URL // http://127.0.0.1:PORT

	fmt.Println("== secskills selftest ==")
	fmt.Printf("local target: %s\n", url)

	target := "selftest-local"
	wd, err := workspace.Workdir(target)
	if err != nil {
		return err
	}
	defer os.RemoveAll(wd)
	workspace.WriteScope(wd, []string{netsec.HostOf(url)})

	pass := true
	check := func(name string, ok bool) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			pass = false
		}
		fmt.Printf("  [%s] %s\n", status, name)
	}

	// 1. check engine produces findings
	hdr := engine.CheckSecurityHeaders(url)
	check(fmt.Sprintf("security headers: %d findings (expect >=3)", len(hdr)), len(hdr) >= 3)
	exp := engine.CheckExposure(url)
	check(fmt.Sprintf("exposure: /metrics found (%d)", len(exp)), len(exp) >= 1)

	// 2. findings store: add + persist + reload
	for i, f := range append(hdr, exp...) {
		f.ID = fmt.Sprintf("ST%03d", i+1)
		finding.AddFinding(wd, f)
	}
	loaded := finding.LoadWorkFindings(wd)
	check(fmt.Sprintf("findings persisted (%d)", len(loaded)), len(loaded) == len(hdr)+len(exp))

	// 3. write-run + latest symlink
	runPath, err := finding.WriteRun(target, wd, "selftest")
	check("run file written", err == nil && textutil.FileExists(runPath))
	defer os.RemoveAll(finding.StoreDir(target))

	// 4. report render
	out := filepath.Join(wd, "report.md")
	check("report renders", report.DoRender(target, out) == nil && textutil.FileExists(out))

	// 5. KB + doctor + registry sanity
	_, kberr := kb.KBClassText("config-exposure")
	check("KB serves config-exposure", kberr == nil)
	check("registry parses >=60 tools", len(tooling.ParseRegistry()) >= 60)

	// 6. scope confinement blocks a foreign host
	check("scope blocks foreign host", !workspace.ScopeCheck(wd, "evil.example.com"))

	fmt.Println()
	if !pass {
		return fmt.Errorf("selftest FAILED")
	}
	fmt.Println("selftest PASSED — discover/check/store/report pipeline verified end-to-end.")
	return nil
}
