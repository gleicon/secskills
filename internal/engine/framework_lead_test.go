package engine

import (
	"net/http"
	"strings"
	"testing"
)

// A servlet container (JSESSIONID + Tomcat body) must emit exactly one
// version-inferred CVE lead, LOW and explicitly not a confirmed finding, since
// the JDK patch level is never on the wire.
func TestFrameworkCVELeadFromServletSurface(t *testing.T) {
	wd := t.TempDir()
	hdr := http.Header{"Set-Cookie": {"JSESSIONID=ABC123; Path=/"}}
	body := "<html><body>Apache Tomcat/9.0.50</body></html>"

	leads := frameworkCVELeads(wd, "https://app.example.com", 200, hdr, body)
	if len(leads) != 1 {
		t.Fatalf("got %d leads, want 1: %+v", len(leads), leads)
	}
	f := leads[0]
	if f.Severity != "LOW" {
		t.Errorf("severity = %q, want LOW", f.Severity)
	}
	if f.Validation != "version-inferred" {
		t.Errorf("validation = %q, want version-inferred", f.Validation)
	}
	if f.DetectorID != "tech.framework-cve-lead@1" {
		t.Errorf("detector = %q", f.DetectorID)
	}
	if !strings.Contains(f.ObservedEvidence, "lead to confirm host-side") {
		t.Errorf("evidence must state it is a lead, got: %s", f.ObservedEvidence)
	}
	if !strings.Contains(f.Title, "Servlet") {
		t.Errorf("title should name the servlet runtime, got %q", f.Title)
	}
	if !strings.Contains(f.ObservedEvidence, "CVE-2026-114938") {
		t.Errorf("Java servlet lead should cite the runtime CVE, got: %s", f.ObservedEvidence)
	}
}

// A plain static response matches no CVE-lead signature, so no lead is emitted.
func TestFrameworkCVELeadNoneForUnknownStack(t *testing.T) {
	wd := t.TempDir()
	hdr := http.Header{"Server": {"nginx/1.25.0"}}
	leads := frameworkCVELeads(wd, "https://static.example.com", 200, hdr, "<html>hello</html>")
	if len(leads) != 0 {
		t.Fatalf("got %d leads, want 0: %+v", len(leads), leads)
	}
}
