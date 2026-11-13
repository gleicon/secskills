package engine

import (
	"fmt"
	"strings"

	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/netsec"
)

// Object-storage enumeration. For a cloud-provider engagement this is a
// first-class module, not an afterthought: candidate bucket names are derived
// from the registrable domain and discovered subdomain labels, then tested for
// anonymous listing across S3 / GCS / Azure Blob. All GET-only, bounded, throttled.

// bucketCandidates builds a bounded, de-duplicated candidate list from the apex
// and discovered labels (e.g. "assets.example.com" -> assets, example-assets, ...).
func bucketCandidates(apex string, labels []string) []string {
	base := strings.SplitN(apex, ".", 2)[0] // "example" from "example.com"
	suffixes := []string{"", "-assets", "-static", "-backup", "-backups", "-media", "-uploads", "-data", "-public", "-dev", "-prod", "-logs", "-cdn"}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.Trim(s, "-."))
		if s != "" && !seen[s] && len(s) >= 3 && len(s) <= 63 {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, suf := range suffixes {
		add(base + suf)
	}
	for _, l := range labels {
		l = strings.SplitN(strings.ToLower(l), ".", 2)[0]
		add(l)
		add(base + "-" + l)
		add(l + "-" + base)
	}
	if len(out) > 40 { // hard budget
		out = out[:40]
	}
	return out
}

// EnumObjectStorage tests candidate buckets for anonymous listing. Returns
// findings for any publicly-listable store.
func EnumObjectStorage(wd, apex string, labels []string) []finding.Finding {
	var out []finding.Finding
	cands := bucketCandidates(apex, labels)
	advProbe("object-storage", len(cands))
	for _, b := range cands {
		for _, probe := range []struct {
			kind, url, sig string
		}{
			{"S3 (virtual-hosted)", "https://" + b + ".s3.amazonaws.com/", "<ListBucketResult"},
			{"S3 (path-style)", "https://s3.amazonaws.com/" + b + "/", "<ListBucketResult"},
			{"Google Cloud Storage", "https://storage.googleapis.com/" + b + "/", "<ListBucketResult"},
			{"Azure Blob", "https://" + b + ".blob.core.windows.net/?comp=list", "<EnumerationResults"},
		} {
			code, _, body, ok := fetch.GetWithBody(probe.url, 32*1024)
			if !ok {
				continue
			}
			if code == 200 && strings.Contains(body, probe.sig) {
				advHit("object-storage")
				ev := finding.CaptureEvidence(wd, "storage.public-bucket@1", probe.url, "http-response", "application/xml", "GET "+probe.url, "redacted",
					[]byte(body[:min(len(body), 8192)]))
				out = append(out, finding.Finding{
					Title: "Public object storage: anonymous listing (" + probe.kind + ", bucket " + b + ")",
					Host:  probe.url, Severity: "HIGH", Status: "open",
					Confidence: "Confirmed", Validation: "behavior-confirmed",
					ObservedEvidence: fmt.Sprintf("Anonymous GET %s returned HTTP 200 with a bucket listing (%s). Object keys are enumerable unauthenticated.", probe.url, probe.kind),
					ImpactText:       "An anonymously-listable object store discloses stored object names and can expose their contents. Restrict the bucket policy and disable anonymous listing.",
					EvidenceCmd:      "curl -sk " + netsec.ShellQuote(probe.url), ProbeKind: "body-contains", ProbeURL: probe.url, ProbeArg: probe.sig,
					EvidenceRefs: []string{ev}, DetectorID: "storage.public-bucket@1", Capabilities: []string{finding.CapAnonRead},
				})
				break // one hit per bucket is enough
			}
		}
	}
	return out
}
