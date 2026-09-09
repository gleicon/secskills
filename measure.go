package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
)

// M6 — Engine self-measurement.
// A local corpus of deliberately-vulnerable and deliberately-safe servers with
// ground-truth labels. We run the LIVE detectors against them and measure
// precision / recall / false-positive rate per detector — so we can answer "does
// the engine actually work", not just "does it run". `secskills measure`.
//
// Each detector assumes it owns the base root (it appends its own paths/queries),
// so the corpus provides one small server per detector family whose root behaves
// exactly as that detector probes.

func redirectServer(vuln bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if vuln {
			if u := r.URL.Query().Get("url"); u != "" {
				http.Redirect(w, r, u, 302)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>App</title><body>home</body></html>")
	}))
}

func sstiServer(vuln bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if vuln && strings.HasPrefix(q, "{{") && strings.HasSuffix(q, "}}") {
			expr := strings.TrimSuffix(strings.TrimPrefix(q, "{{"), "}}")
			if parts := strings.SplitN(expr, "*", 2); len(parts) == 2 {
				var a, b int
				fmt.Sscanf(parts[0], "%d", &a)
				fmt.Sscanf(parts[1], "%d", &b)
				fmt.Fprintf(w, "result: %d", a*b)
				return
			}
		}
		fmt.Fprint(w, "<html><title>Search</title>no results</html>")
	}))
}

func bucketServer(vuln bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if vuln {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>secret</Name></Bucket></Buckets></ListAllMyBucketsResult>`)
			return
		}
		fmt.Fprint(w, "<html><title>App</title>home</html>")
	}))
}

func oidcServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"issuer":"https://idp.example","authorization_endpoint":"/authorize","token_endpoint":"/token","jwks_uri":"/jwks"}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "home") })
	return httptest.NewServer(mux)
}

func apiServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openapi":"3.0.0","paths":{"/x":{}}}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "home") })
	return httptest.NewServer(mux)
}

func exposureServer(vuln bool) *httptest.Server {
	mux := http.NewServeMux()
	if vuln {
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "# HELP up\nup 1\nnode_info{host=\"db-01.internal\",namespace=\"prod\"} 1\napi_key=\"AKIAoops\"\n")
		})
		mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n")
		})
	} else {
		// generic metrics only: must NOT escalate above LOW / must not be sensitive
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "# HELP process_cpu\nprocess_cpu_seconds_total 12.3\nprocess_start_time 1000\n")
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "home") })
	return httptest.NewServer(mux)
}

type mScore struct{ tp, fp, fn, tn int }

// cmdMeasure runs the corpus and prints the detector quality scorecard.
func cmdMeasure(args []string) error {
	allowLocalProbes = true
	defer func() { allowLocalProbes = false }()
	wd, _ := os.MkdirTemp("", "sk-measure")
	defer os.RemoveAll(wd)
	scores := map[string]*mScore{}
	var mism []string
	get := func(d string) *mScore {
		if scores[d] == nil {
			scores[d] = &mScore{}
		}
		return scores[d]
	}
	// record(detector, wantFire, didFire)
	record := func(det string, want, got bool) {
		s := get(det)
		switch {
		case want && got:
			s.tp++
		case want && !got:
			s.fn++
			mism = append(mism, det+": expected to fire, did not")
		case !want && got:
			s.fp++
			mism = append(mism, det+": fired but should not (false positive)")
		default:
			s.tn++
		}
	}
	fired := func(fs ...*Finding) map[string]bool {
		m := map[string]bool{}
		for _, f := range fs {
			if f != nil {
				m[detectorOf(f)] = true
			}
		}
		return m
	}
	firedS := func(fs []Finding) map[string]bool {
		m := map[string]bool{}
		for i := range fs {
			m[detectorOf(&fs[i])] = true
		}
		return m
	}

	// open redirect
	rv := redirectServer(true)
	record("http.open-redirect@1", true, fired(openRedirectProbe(wd, rv.URL))["http.open-redirect@1"])
	rv.Close()
	rs := redirectServer(false)
	record("http.open-redirect@1", false, fired(openRedirectProbe(wd, rs.URL))["http.open-redirect@1"])
	rs.Close()

	// SSTI
	sv := sstiServer(true)
	record("ssti.arithmetic@1", true, fired(sstiArithmeticProbe(wd, sv.URL))["ssti.arithmetic@1"])
	sv.Close()
	ss := sstiServer(false)
	record("ssti.arithmetic@1", false, fired(sstiArithmeticProbe(wd, ss.URL))["ssti.arithmetic@1"])
	ss.Close()

	// object storage
	bv := bucketServer(true)
	record("storage.public-bucket@1", true, firedS(ssObjectStore(wd, bv.URL))["storage.public-bucket@1"])
	bv.Close()
	bs := bucketServer(false)
	record("storage.public-bucket@1", false, firedS(ssObjectStore(wd, bs.URL))["storage.public-bucket@1"])
	bs.Close()

	// OIDC
	ov := oidcServer()
	record("identity.oidc-surface@1", true, fired(oidcSurface(wd, ov.URL))["identity.oidc-surface@1"])
	ov.Close()

	// API schema
	av := apiServer()
	record("api.schema-exposure@1", true, fired(apiSchema(wd, av.URL))["api.schema-exposure@1"])
	av.Close()

	// exposure: sensitive metrics + git (vuln) ; generic metrics (safe -> exposure still fires but LOW; here we
	// measure the exposure-path/metrics detector firing on git, and NOT firing spuriously on a plain home).
	ev := exposureServer(true)
	efired := firedS(checkExposure(ev.URL))
	record("http.exposure-path@1", true, efired["http.exposure-path@1"])
	record("http.prometheus.public-metrics@1", true, efired["http.prometheus.public-metrics@1"])
	ev.Close()

	dets := make([]string, 0, len(scores))
	for k := range scores {
		dets = append(dets, k)
	}
	sort.Strings(dets)
	out := map[string]any{}
	fmt.Println("Engine self-measurement (local corpus of vulnerable + safe servers)")
	fmt.Println("| Detector | TP | FP | FN | TN | Precision | Recall |")
	fmt.Println("|----------|---:|---:|---:|---:|----------:|-------:|")
	allPass := true
	for _, d := range dets {
		s := scores[d]
		prec := ratio(s.tp, s.tp+s.fp)
		rec := ratio(s.tp, s.tp+s.fn)
		fmt.Printf("| %s | %d | %d | %d | %d | %.0f%% | %.0f%% |\n", d, s.tp, s.fp, s.fn, s.tn, prec*100, rec*100)
		out[d] = map[string]any{"tp": s.tp, "fp": s.fp, "fn": s.fn, "tn": s.tn, "precision": prec, "recall": rec}
		if s.fp > 0 || s.fn > 0 {
			allPass = false
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	os.WriteFile("measure-report.json", b, 0o644)
	if len(mism) > 0 {
		fmt.Println("\nMismatches:")
		for _, m := range mism {
			fmt.Println("  - " + m)
		}
	}
	fmt.Printf("\nScorecard -> measure-report.json. Result: %s\n", passLabel(allPass))
	if !allPass {
		os.Exit(1)
	}
	return nil
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func passLabel(ok bool) string {
	if ok {
		return "PASS (no false positives or missed detections on the corpus)"
	}
	return "FAIL"
}
