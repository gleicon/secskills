package exposure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gleicon/secskills/internal/finding"
	"github.com/gleicon/secskills/internal/intel"
)

func byID(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func TestNetworkFindingsFollowTheSeverityRubric(t *testing.T) {
	wd := t.TempDir()
	leaks := []LeakFinding{
		{IP: "203.0.113.10", Port: 80, URL: "http://203.0.113.10/.git/config", Kind: "exposed-vcs", Evidence: "git config exposed: [core]"},
		{IP: "203.0.113.10", Port: 80, URL: "http://203.0.113.10/.env", Kind: "exposed-dotenv", Evidence: "dotenv exposed: 2 keys [DB_PASSWORD, APP_KEY] (values redacted)"},
		{IP: "203.0.113.30", Port: 6379, Kind: "redis-unauth", Evidence: "PING -> PONG without AUTH"},
		{IP: "203.0.113.10", Port: 80, Kind: "banner", Evidence: "Server: nginx"},
	}
	dbs := []DBResult{
		{IP: "203.0.113.31", Port: 9200, Service: "elasticsearch", Status: "DEFAULT-CRED", Detail: "elastic accepted"},
		{IP: "203.0.113.32", Port: 3306, Service: "mysql", Status: "AUTH-ENFORCED"},
	}
	cve := []ServiceMatch{
		{Obs: Observation{IP: "203.0.113.10", Port: 22, Product: "OpenSSH", Version: "8.9p1"},
			Cands: []intel.Candidate{{AssetIP: "203.0.113.10", CVE: "CVE-2024-6387", Score: 0.27, ScoreTerms: map[string]float64{"cvss": 8.1, "epss": 0.99}}}},
		{Obs: Observation{IP: "203.0.113.10", Port: 80, Product: "nginx", Version: "1.18.0"},
			Cands: []intel.Candidate{
				{AssetIP: "203.0.113.10", CVE: "CVE-2021-23017", Score: 0.1, ScoreTerms: map[string]float64{"cvss": 7.7}},
				{AssetIP: "203.0.113.10", CVE: "CVE-2023-44487", Score: 0.5, ScoreTerms: map[string]float64{"cvss": 7.5}}}},
	}
	kev := map[string]bool{"CVE-2023-44487": true}
	for fam, fs := range map[string][]finding.Finding{FamilyLeak: LeakFindings(leaks), FamilyDB: DBFindings(dbs), FamilyCVE: CVEFindings(cve, kev)} {
		if _, err := SyncFindings(wd, fam, fs); err != nil {
			t.Fatal(err)
		}
	}
	got := byID(finding.LoadWorkFindings(wd))
	want := map[string]string{
		"NET-LEAK-203.0.113.10:80-exposed-vcs":    "HIGH",   // reachable .git: source + history retrievable
		"NET-LEAK-203.0.113.10:80-exposed-dotenv": "HIGH",   // reachable .env: application credentials
		"NET-LEAK-203.0.113.30:6379-redis-unauth": "HIGH",   // confirmed unauthenticated datastore
		"NET-DB-203.0.113.31:9200":                "HIGH",   // vendor default credential accepted
		"NET-CVE-203.0.113.10:22":                 "LOW",    // version-inferred lead
		"NET-CVE-203.0.113.10:80":                 "MEDIUM", // lead including a KEV-listed CVE
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d: %v", len(got), len(want), got)
	}
	for id, sev := range want {
		f, ok := got[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s severity %s, want %s", id, f.Severity, sev)
		}
		if f.Key == "" || f.DetectorID == "" || f.OWASP == "" {
			t.Errorf("%s lacks key/detector/OWASP mapping: %+v", id, f)
		}
	}
	if got["NET-LEAK-203.0.113.10:80-exposed-dotenv"].Severity != "HIGH" {
		t.Error("dotenv with credential keys is a confirmed credential disclosure -> HIGH")
	}
	vcs := got["NET-LEAK-203.0.113.10:80-exposed-vcs"]
	if vcs.ProbeKind != "body-contains" || vcs.ProbeArg != "repositoryformatversion" {
		t.Errorf("exposed .git must be retestable, got %q %q", vcs.ProbeKind, vcs.ProbeArg)
	}
	nginx := got["NET-CVE-203.0.113.10:80"]
	if nginx.CVEs[0] != "CVE-2023-44487" {
		t.Errorf("KEV CVE must sort first, got %v", nginx.CVEs)
	}
}

func TestNetworkFindingsCarryNoSecretValues(t *testing.T) {
	l := LeakFinding{IP: "203.0.113.10", Port: 80, URL: "http://203.0.113.10/.env", Kind: "exposed-dotenv",
		Evidence: redactEnv("DB_PASSWORD=hunter2\nAPI_KEY=sk-live-123\n")}
	for _, f := range LeakFindings([]LeakFinding{l}) {
		blob := f.Title + f.ObservedEvidence + f.EvidenceCmd + f.ProbeArg + strings.Join(f.References, " ")
		for _, secret := range []string{"hunter2", "sk-live-123"} {
			if strings.Contains(blob, secret) {
				t.Fatalf("finding carries secret %q: %s", secret, blob)
			}
		}
		if f.ProbeArg != "DB_PASSWORD=" {
			t.Errorf("retest pattern %q, want the key name only", f.ProbeArg)
		}
	}
}

func TestSyncFindingsTransitions(t *testing.T) {
	wd := t.TempDir()
	lead := func(ip string) finding.Finding {
		return CVEFindings([]ServiceMatch{{Obs: Observation{IP: ip, Port: 22, Product: "OpenSSH", Version: "8.9p1"},
			Cands: []intel.Candidate{{AssetIP: ip, CVE: "CVE-2024-6387"}}}}, nil)[0]
	}
	a, b := lead("203.0.113.1"), lead("203.0.113.2")

	r, _ := SyncFindings(wd, FamilyCVE, []finding.Finding{a, b})
	if r.Opened != 2 {
		t.Fatalf("first run: %v", r)
	}
	// operator accepts b's risk
	ws := finding.LoadWorkFindings(wd)
	for i := range ws {
		if ws[i].ID == b.ID {
			ws[i].Status = "accepted"
			finding.AddFinding(wd, ws[i])
		}
	}
	// re-run: a no longer matches, b still does
	r, _ = SyncFindings(wd, FamilyCVE, []finding.Finding{b})
	got := byID(finding.LoadWorkFindings(wd))
	if got[a.ID].Status != "mitigated" || got[a.ID].FixedAt == "" || r.Closed != 1 {
		t.Errorf("a should close as mitigated: %+v %v", got[a.ID].Status, r)
	}
	if got[b.ID].Status != "accepted" {
		t.Errorf("accepted decision lost: %s", got[b.ID].Status)
	}
	// re-run: a is back
	r, _ = SyncFindings(wd, FamilyCVE, []finding.Finding{a, b})
	got = byID(finding.LoadWorkFindings(wd))
	if got[a.ID].Status != "open" || got[a.ID].RegressedAt == "" || r.Regressed != 1 {
		t.Errorf("a should reopen as regressed: %+v %v", got[a.ID].Status, r)
	}
	if len(got) != 2 {
		t.Errorf("re-runs must update, not duplicate: %d findings", len(got))
	}
	// other families are untouched by a CVE sync
	SyncFindings(wd, FamilyLeak, LeakFindings([]LeakFinding{{IP: "203.0.113.9", Port: 6379, Kind: "redis-unauth"}}))
	SyncFindings(wd, FamilyCVE, nil)
	got = byID(finding.LoadWorkFindings(wd))
	if got["NET-LEAK-203.0.113.9:6379-redis-unauth"].Status != "open" {
		t.Error("a CVE sync closed a leak finding")
	}
}

func TestInventory(t *testing.T) {
	wd := t.TempDir()
	if Inventory(wd) != "" {
		t.Fatal("no observations should render nothing")
	}
	obs := `{"ip":"203.0.113.10","port":22,"service":"ssh","product":"OpenSSH","version":"8.9p1","source":"banner","confidence":"medium","observed_at":"2026-11-01T00:00:00Z","fingerprint_version":1}
{"ip":"203.0.113.9","port":6379,"service":"redis","source":"connect","confidence":"low","observed_at":"2026-11-01T00:00:00Z","fingerprint_version":1}
`
	os.WriteFile(filepath.Join(wd, "enriched-observations.jsonl"), []byte(obs), 0o600)
	inv := Inventory(wd)
	for _, want := range []string{"2 hosts, 2 open services", "`203.0.113.9:6379` redis", "22/ssh OpenSSH 8.9p1"} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventory missing %q:\n%s", want, inv)
		}
	}
	if strings.Index(inv, "203.0.113.9`") > strings.Index(inv, "203.0.113.10`") {
		t.Error("hosts must sort numerically")
	}
}

func TestSvcTallyDeterministic(t *testing.T) {
	m := map[string]int{"ssh": 2, "http": 2, "redis": 1, "https": 1, "smtp": 3}
	want := "smtp 3, http 2, ssh 2, https 1, redis 1"
	for i := 0; i < 50; i++ {
		if got := svcTally(m); got != want {
			t.Fatalf("svcTally = %q, want %q", got, want)
		}
	}
}

func TestLeakEvidenceCommandIsSafeToPaste(t *testing.T) {
	l := LeakFinding{IP: "203.0.113.10", Port: 80, Kind: "exposed-dotenv",
		URL:      "http://203.0.113.10/.env';id;'",
		Evidence: "dotenv exposed: 3 keys [$(touch /tmp/pwn), A';id;', DB_PASSWORD] (values redacted)"}
	f := LeakFindings([]LeakFinding{l})[0]
	if f.ProbeArg != "DB_PASSWORD=" {
		t.Errorf("malformed key names must be dropped, got signature %q", f.ProbeArg)
	}
	if strings.Contains(f.ObservedEvidence, "credential-like keys exposed (values redacted): $(") {
		t.Error("malformed key name reached the evidence key list")
	}
	want := `curl -s 'http://203.0.113.10/.env'\''`
	if !strings.HasPrefix(f.EvidenceCmd, want) || !strings.HasSuffix(f.EvidenceCmd, `grep -c 'DB_PASSWORD='`) {
		t.Errorf("evidence command not quoted: %s", f.EvidenceCmd)
	}
}

func TestShardPrefixesDeterministicOnTies(t *testing.T) {
	in := []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24"}
	first := ShardPrefixes(in, 2)
	for i := 0; i < 50; i++ {
		got := ShardPrefixes(in, 2)
		for s := range got {
			if strings.Join(got[s].Prefixes, ",") != strings.Join(first[s].Prefixes, ",") {
				t.Fatalf("equal-size prefixes landed in different shards between runs")
			}
		}
	}
}
