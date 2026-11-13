package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gleicon/secskills/internal/finding"
)

func sample() []finding.Finding {
	return []finding.Finding{
		{ID: "F-1", Title: "TLS 1.0 enabled", Host: "app.example.com:443", Severity: "MEDIUM", Key: "k-tls"},
		{ID: "F-2", Title: "TLS 1.1 enabled", Host: "app.example.com:443", Severity: "HIGH", Key: "k-tls"},
		{ID: "F-3", Title: "Exposed .git directory", Host: "https://app.example.com/.git/HEAD", Severity: "CRITICAL", Key: "k-git"},
	}
}

func TestPriorityFor(t *testing.T) {
	for sev, want := range map[string]string{"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFORMATIONAL": "P5", "": "P5"} {
		if got := PriorityFor(sev); got != want {
			t.Errorf("PriorityFor(%q) = %s, want %s", sev, got, want)
		}
	}
}

func TestDedupeByKeyKeepsHighestSeverity(t *testing.T) {
	out := DedupeByKey(sample())
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2", len(out))
	}
	if out[0].ID != "F-2" || out[1].ID != "F-3" {
		t.Errorf("order/selection wrong: %s, %s", out[0].ID, out[1].ID)
	}
}

func TestBuildSARIFShape(t *testing.T) {
	b, err := json.Marshal(BuildSARIF("app.example.com", sample()))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string           `json:"name"`
					Rules []map[string]any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "secskills" {
		t.Fatalf("bad SARIF envelope: %s", b)
	}
	run := doc.Runs[0]
	if len(run.Results) != 3 {
		t.Fatalf("%d results, want 3", len(run.Results))
	}
	for _, r := range run.Results {
		if r.RuleIndex >= len(run.Tool.Driver.Rules) || run.Tool.Driver.Rules[r.RuleIndex]["id"] != r.RuleID {
			t.Errorf("result %s points at wrong rule index %d", r.RuleID, r.RuleIndex)
		}
		switch r.Level {
		case "error", "warning", "note", "none":
		default:
			t.Errorf("invalid SARIF level %q", r.Level)
		}
	}
}

func TestBuildCycloneDXShape(t *testing.T) {
	b, _ := json.Marshal(BuildCycloneDX("app.example.com", sample()))
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.5" {
		t.Fatalf("bad CycloneDX envelope: %s", b)
	}
}

func TestRunManifestSignVerifyTamper(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	wd := t.TempDir()
	meta := filepath.Join(wd, "run-meta.json")
	os.WriteFile(meta, []byte(`{"run":"r1"}`), 0o644)
	if _, err := SignRunManifest(wd); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRunManifest(wd); err != nil {
		t.Fatalf("fresh signature rejected: %v", err)
	}
	os.WriteFile(meta, []byte(`{"run":"r2"}`), 0o644)
	if err := VerifyRunManifest(wd); err == nil {
		t.Fatal("tampered run-meta.json accepted")
	}
	os.WriteFile(meta, []byte(`{"run":"r1"}`), 0o644)
	env := filepath.Join(wd, "run-attestation.sig")
	var e DSSEEnvelope
	b, _ := os.ReadFile(env)
	json.Unmarshal(b, &e)
	e.Payload = "eyJydW4iOiJyMyJ9" // {"run":"r3"}
	b, _ = json.Marshal(e)
	os.WriteFile(env, b, 0o644)
	if err := VerifyRunManifest(wd); err == nil {
		t.Fatal("forged envelope payload accepted")
	}
}
