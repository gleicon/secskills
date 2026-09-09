package main

import "testing"

// TestEngineMeasurementCorpus is the engine self-measurement gate: every live
// detector must fire on the deliberately-vulnerable corpus server and stay
// silent on the deliberately-safe one. This caught a real SSTI product-constant
// bug (the detector would never have fired in production).
func TestEngineMeasurementCorpus(t *testing.T) {
	allowLocalProbes = true
	defer func() { allowLocalProbes = false }()
	wd := t.TempDir()

	check := func(det string, wantVuln bool, gotVuln, gotSafe map[string]bool) {
		if wantVuln && !gotVuln[det] {
			t.Errorf("%s: expected to fire on vulnerable corpus, did not", det)
		}
		if gotSafe != nil && gotSafe[det] {
			t.Errorf("%s: fired on SAFE corpus (false positive)", det)
		}
	}
	firedOf := func(fs ...*Finding) map[string]bool {
		m := map[string]bool{}
		for _, f := range fs {
			if f != nil {
				m[detectorOf(f)] = true
			}
		}
		return m
	}
	firedSl := func(fs []Finding) map[string]bool {
		m := map[string]bool{}
		for i := range fs {
			m[detectorOf(&fs[i])] = true
		}
		return m
	}

	rv := redirectServer(true)
	rs := redirectServer(false)
	check("http.open-redirect@1", true, firedOf(openRedirectProbe(wd, rv.URL)), firedOf(openRedirectProbe(wd, rs.URL)))
	rv.Close()
	rs.Close()

	sv := sstiServer(true)
	ss := sstiServer(false)
	check("ssti.arithmetic@1", true, firedOf(sstiArithmeticProbe(wd, sv.URL)), firedOf(sstiArithmeticProbe(wd, ss.URL)))
	sv.Close()
	ss.Close()

	bv := bucketServer(true)
	bs := bucketServer(false)
	check("storage.public-bucket@1", true, firedSl(ssObjectStore(wd, bv.URL)), firedSl(ssObjectStore(wd, bs.URL)))
	bv.Close()
	bs.Close()

	ov := oidcServer()
	check("identity.oidc-surface@1", true, firedOf(oidcSurface(wd, ov.URL)), nil)
	ov.Close()

	av := apiServer()
	check("api.schema-exposure@1", true, firedOf(apiSchema(wd, av.URL)), nil)
	av.Close()

	ev := exposureServer(true)
	ef := firedSl(checkExposure(ev.URL))
	check("http.exposure-path@1", true, ef, nil)
	check("http.prometheus.public-metrics@1", true, ef, nil)
	ev.Close()
}
