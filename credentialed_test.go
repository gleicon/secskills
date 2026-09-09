package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func mkJWT(hdr, payload string) string {
	e := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return e(hdr) + "." + e(payload) + ".sig"
}

// TestJWTInspect proves the JWT detector flags alg:none and missing-exp.
func TestJWTInspect(t *testing.T) {
	none := mkJWT(`{"alg":"none","typ":"JWT"}`, `{"sub":"u1"}`)
	fs := jwtInspect(none)
	sawNone, sawNoExp := false, false
	for _, f := range fs {
		if strings.Contains(f.Title, "alg:none") {
			sawNone = true
			if f.Severity != "HIGH" {
				t.Errorf("alg:none severity = %s, want HIGH", f.Severity)
			}
		}
		if strings.Contains(f.Title, "no expiry") {
			sawNoExp = true
		}
	}
	if !sawNone {
		t.Error("did not flag alg:none")
	}
	if !sawNoExp {
		t.Error("did not flag missing exp")
	}
	// a well-formed non-JWT string must produce nothing
	if len(jwtInspect("not-a-jwt")) != 0 {
		t.Error("non-JWT should yield no findings")
	}
}

// TestObjectURLHeuristic guards the BOLA object-URL heuristic.
func TestObjectURLHeuristic(t *testing.T) {
	if !looksLikeObjectURL("https://h/api/users/12345") {
		t.Error("numeric id path should look like an object URL")
	}
	if looksLikeObjectURL("https://h/about") {
		t.Error("static path should not look like an object URL")
	}
}
