package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	wd := workdir(target)
	defer os.RemoveAll(wd)
	writeScope(wd, []string{hostOf(url)})

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
	hdr := checkSecurityHeaders(url)
	check(fmt.Sprintf("security headers: %d findings (expect >=3)", len(hdr)), len(hdr) >= 3)
	exp := checkExposure(url)
	check(fmt.Sprintf("exposure: /metrics found (%d)", len(exp)), len(exp) >= 1)

	// 2. findings store: add + persist + reload
	for i, f := range append(hdr, exp...) {
		f.ID = fmt.Sprintf("ST%03d", i+1)
		addFinding(wd, f)
	}
	loaded := loadWorkFindings(wd)
	check(fmt.Sprintf("findings persisted (%d)", len(loaded)), len(loaded) == len(hdr)+len(exp))

	// 3. write-run + latest symlink
	runPath, err := writeRun(target, wd, "selftest")
	check("run file written", err == nil && fileExists(runPath))
	defer os.RemoveAll(storeDir(target))

	// 4. report render
	out := filepath.Join(wd, "report.md")
	check("report renders", doRender(target, out) == nil && fileExists(out))

	// 5. KB + doctor + registry sanity
	_, kberr := kbClassText("config-exposure")
	check("KB serves config-exposure", kberr == nil)
	check("registry parses >=60 tools", len(parseRegistry()) >= 60)

	// 6. scope confinement blocks a foreign host
	check("scope blocks foreign host", !scopeCheck(wd, "evil.example.com"))

	fmt.Println()
	if !pass {
		return fmt.Errorf("selftest FAILED")
	}
	fmt.Println("selftest PASSED — discover/check/store/report pipeline verified end-to-end.")
	return nil
}
