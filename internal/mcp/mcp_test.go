package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func call(t *testing.T, method string, params any) (RPCResp, bool) {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		raw = b
	}
	return DispatchMCP(RPCReq{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: raw})
}

func text(t *testing.T, r RPCResp) string {
	t.Helper()
	b, _ := json.Marshal(r.Result)
	var res struct {
		Content []struct{ Text string } `json:"content"`
	}
	if err := json.Unmarshal(b, &res); err != nil || len(res.Content) != 1 {
		t.Fatalf("unexpected result shape: %s", b)
	}
	return res.Content[0].Text
}

func TestToolsListIsReadOnly(t *testing.T) {
	r, _ := call(t, "tools/list", nil)
	b, _ := json.Marshal(r.Result)
	var res struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	json.Unmarshal(b, &res)
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	got := strings.Join(names, ",")
	if got != "doctor,kb_list,kb_get,recipes_get,source_scan,fetch" {
		// A new tool must be reviewed: no MCP tool may trigger a scan.
		t.Fatalf("tool set changed: %s", got)
	}
}

func TestFetchRefusesInternalTargets(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "http://10.0.0.1/"} {
		r, _ := call(t, "tools/call", map[string]any{"name": "fetch", "arguments": map[string]string{"source": "osv", "url": u}})
		if got := text(t, r); !strings.HasPrefix(got, "refused:") {
			t.Errorf("fetch %s = %q, want refusal", u, got)
		}
	}
}

func TestDispatchProtocol(t *testing.T) {
	if _, notify := call(t, "notifications/initialized", nil); !notify {
		t.Error("notification must not produce a response")
	}
	r, _ := call(t, "no/such", nil)
	if r.Error == nil || r.Error.Code != -32601 {
		t.Errorf("unknown method: %+v", r.Error)
	}
	r, _ = call(t, "initialize", map[string]any{})
	if r.Error != nil || r.JSONRPC != "2.0" || string(r.ID) != "1" {
		t.Errorf("initialize: %+v", r)
	}
	r, _ = call(t, "tools/call", map[string]any{"name": "kb_get", "arguments": map[string]string{"class": "../../etc/passwd"}})
	if got := text(t, r); !strings.HasPrefix(got, "error:") {
		t.Errorf("kb_get traversal = %q, want error", got)
	}
	r, _ = call(t, "tools/call", map[string]any{"name": "kb_get", "arguments": map[string]string{"class": "injection"}})
	if got := text(t, r); !strings.Contains(got, "class: injection") {
		t.Errorf("kb_get injection missing front matter: %.80q", got)
	}
}
