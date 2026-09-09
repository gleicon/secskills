package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Item 3 — Immutable evidence objects.
// A finding is a derived assertion over immutable evidence. Each captured
// artifact (HTTP response, TLS transcript, DNS answer, cert, detector parse) is
// written once to the workdir evidence store, addressed by a content-derived
// EV-id, and referenced by findings. Nothing rewrites an evidence object.
type EvidenceObject struct {
	ID             string `json:"evidence_id"`
	RunID          string `json:"run_id"`
	AssetID        string `json:"asset_id"`
	DetectorID     string `json:"detector_id"`
	Type           string `json:"type"` // http-response|tls-transcript|dns|certificate|screenshot|detector-parse
	MIME           string `json:"mime"`
	SHA256         string `json:"sha256"`
	ParentRequest  string `json:"parent_request,omitempty"`
	RedactionState string `json:"redaction_status"` // none|redacted
	Timestamp      string `json:"timestamp"`
	Path           string `json:"path"`
}

func evidenceDir(wd string) string { return filepath.Join(wd, "evidence") }

// captureEvidence writes one immutable evidence object and returns its EV-id.
// The id is content-addressed (detector+asset+content), so identical evidence
// dedupes and the id is reproducible.
func captureEvidence(wd, detectorID, asset, typ, mime, parentReq, redaction string, content []byte) string {
	sum := sha256.Sum256(content)
	seed := sha256.Sum256([]byte(detectorID + "|" + normalizedAsset(asset) + "|" + typ + "|" + fmt.Sprintf("%x", sum)))
	id := "EV-" + fmt.Sprintf("%x", seed[:5])
	dir := evidenceDir(wd)
	os.MkdirAll(dir, 0o755)
	blob := filepath.Join(dir, id+".blob")
	if _, err := os.Stat(blob); err != nil {
		os.WriteFile(blob, content, 0o600)
	}
	obj := EvidenceObject{
		ID: id, RunID: readRunID(wd), AssetID: normalizedAsset(asset), DetectorID: detectorID,
		Type: typ, MIME: mime, SHA256: fmt.Sprintf("%x", sum), ParentRequest: parentReq,
		RedactionState: redaction, Timestamp: time.Now().UTC().Format(time.RFC3339),
		Path: "evidence/" + id + ".blob",
	}
	appendManifest(wd, obj)
	return id
}

func readRunID(wd string) string {
	b, err := os.ReadFile(filepath.Join(wd, "run-meta.json"))
	if err != nil {
		return ""
	}
	var m RunMeta
	json.Unmarshal(b, &m)
	return m.RunID
}

// appendManifest keeps evidence-manifest.jsonl append-only (one object per line).
func appendManifest(wd string, obj EvidenceObject) {
	f, err := os.OpenFile(filepath.Join(wd, "evidence-manifest.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(obj)
	f.Write(append(b, '\n'))
}

// loadEvidenceManifest reads all evidence objects for a run.
func loadEvidenceManifest(wd string) []EvidenceObject {
	b, err := os.ReadFile(filepath.Join(wd, "evidence-manifest.jsonl"))
	if err != nil {
		return nil
	}
	var out []EvidenceObject
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var o EvidenceObject
		if json.Unmarshal([]byte(line), &o) == nil {
			out = append(out, o)
		}
	}
	return out
}

// renderEvidenceIndex lists the immutable evidence objects with their hashes —
// the audit index that lets a finding be verified without re-touching the target.
func renderEvidenceIndex(wd string) string {
	objs := loadEvidenceManifest(wd)
	if len(objs) == 0 {
		return "_No immutable evidence objects were captured for this run._"
	}
	var b strings.Builder
	b.WriteString("| Evidence ID | Type | Asset | Detector | SHA-256 | Redaction |\n|---|---|---|---|---|---|\n")
	for _, o := range objs {
		b.WriteString(fmt.Sprintf("| `%s` | %s | %s | `%s` | `%s` | %s |\n",
			o.ID, o.Type, safeField(o.AssetID), o.DetectorID, o.SHA256[:16]+"…", o.RedactionState))
	}
	b.WriteString("\n_Each finding references the evidence objects it derives from. Objects are content-addressed and append-only; the bundle hash in the Run Attestation covers them._")
	return b.String()
}

// M11 — Tamper-evident evidence chain.
// evidenceChainRoot computes a deterministic hash chain over the evidence
// manifest (sorted by id): root_i = sha256(root_{i-1} | id | sha256). Altering or
// removing any evidence object changes the root. The root is signed separately
// from run-meta, so evidence integrity is provable independently of the findings.
func evidenceChainRoot(wd string) string {
	objs := loadEvidenceManifest(wd)
	ids := make([]string, 0, len(objs))
	byID := map[string]EvidenceObject{}
	for _, o := range objs {
		ids = append(ids, o.ID)
		byID[o.ID] = o
	}
	sort.Strings(ids)
	root := ""
	for _, id := range ids {
		o := byID[id]
		h := sha256.Sum256([]byte(root + "|" + id + "|" + o.SHA256))
		root = fmt.Sprintf("%x", h[:])
	}
	return root
}
