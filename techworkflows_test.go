package main

import "testing"

func TestTechWorkflowDispatch(t *testing.T) {
	cases := map[string]bool{
		"MinIO": true, "Amazon S3": true, "Object Storage": true,
		"Harbor": true, "Kong": true, "Grafana": true,
		"Elasticsearch": true, "Vault": true,
		"something-else": false, "": false,
	}
	for name, want := range cases {
		got := techWorkflowFor(name) != nil
		if got != want {
			t.Errorf("techWorkflowFor(%q) != nil = %v, want %v", name, got, want)
		}
	}
	if n := len(kongWorkflow()); n != 1 {
		t.Errorf("kongWorkflow steps = %d, want 1", n)
	}
	if n := len(grafanaWorkflow()); n != 2 {
		t.Errorf("grafanaWorkflow steps = %d, want 2", n)
	}
}

func TestJoinBase(t *testing.T) {
	if got := joinBase("http://x/", "/a"); got != "http://x/a" {
		t.Errorf("joinBase = %q, want http://x/a", got)
	}
	if got := joinBase("http://x//", "/"); got != "http://x/" {
		t.Errorf("joinBase root = %q, want http://x/", got)
	}
}

func TestRunTechWorkflowBreak(t *testing.T) {
	wd := t.TempDir()
	ran := 0
	steps := []wfStep{
		{capAnonRead, "first", func(base string) (string, string, *Finding) {
			ran++
			return "no target here", "STOP_NO_REACHABLE_TARGET", nil
		}},
		{capAnonRead, "second-must-not-run", func(base string) (string, string, *Finding) {
			ran++
			return "should not run", "", nil
		}},
	}
	out := runTechWorkflow(wd, "h", "http://example.test", "testtech", steps, 3)
	if len(out) != 0 {
		t.Errorf("expected no findings, got %d", len(out))
	}
	if ran != 1 {
		t.Errorf("expected break after 1 step, ran %d", ran)
	}
}
