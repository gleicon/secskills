package mcp

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/gleicon/secskills"
	"github.com/gleicon/secskills/internal/fetch"
	"github.com/gleicon/secskills/internal/kb"
	"github.com/gleicon/secskills/internal/netsec"
	"github.com/gleicon/secskills/internal/tooling"
)

// RPCReq is one JSON-RPC 2.0 request line.
type RPCReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// RPCResp is a JSON-RPC 2.0 response.
type RPCResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCErr         `json:"error,omitempty"`
}

// RPCErr is a JSON-RPC 2.0 error object.
type RPCErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// DispatchMCP handles one request. The bool is true for notifications, which
// get no response.
func DispatchMCP(req RPCReq) (RPCResp, bool) {
	r := RPCResp{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		r.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "secskills", "version": secskills.Version},
		}
	case "notifications/initialized":
		return r, true
	case "tools/list":
		r.Result = map[string]any{"tools": mcpTools()}
	case "tools/call":
		r.Result = mcpCall(req.Params)
	default:
		r.Error = &RPCErr{Code: -32601, Message: "method not found: " + req.Method}
	}
	return r, false
}

func mcpTools() []map[string]any {
	strProp := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	return []map[string]any{
		{"name": "doctor", "description": "Check security tools present/missing per mode/category with install commands.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
				"mode": strProp("source|discover|test|sandbox|live|all"), "category": strProp("optional category filter")}}},
		{"name": "kb_list", "description": "List OWASP knowledge-base classes.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}}},
		{"name": "kb_get", "description": "Get OWASP cheat-sheet content for a class (" + kb.KBSummary() + ").",
			"inputSchema": map[string]any{"type": "object", "required": []string{"class"},
				"properties": map[string]any{"class": strProp("KB class name")}}},
		{"name": "recipes_get", "description": "Get per-stack (Node/Python/Go) secure-vs-vulnerable recipe for a class (" + strings.Join(kb.RecipeNames(), ", ") + ").",
			"inputSchema": map[string]any{"type": "object", "required": []string{"name"},
				"properties": map[string]any{"name": strProp("recipe name")}}},
		{"name": "source_scan", "description": "Run embedded ast-grep rules over a source path (static, no network).",
			"inputSchema": map[string]any{"type": "object", "required": []string{"path"},
				"properties": map[string]any{"path": strProp("path to scan")}}},
		{"name": "fetch", "description": "Throttled GET of a free OSINT source (crtsh|wayback|osv|...).",
			"inputSchema": map[string]any{"type": "object", "required": []string{"source", "url"},
				"properties": map[string]any{"source": strProp("source key"), "url": strProp("URL")}}},
	}
}

func textResult(s string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
}

func mcpCall(params json.RawMessage) map[string]any {
	var p struct {
		Name string         `json:"name"`
		Args map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return textResult("bad params: " + err.Error())
	}
	str := func(k string) string {
		if v, ok := p.Args[k].(string); ok {
			return v
		}
		return ""
	}
	switch p.Name {
	case "doctor":
		mode := str("mode")
		if mode == "" {
			mode = "all"
		}
		return textResult(doctorText(mode, orAll(str("category"))))
	case "kb_list":
		out := "OWASP KB classes:\n"
		for _, c := range kb.KBClasses() {
			out += "  " + c + "\n"
		}
		return textResult(out)
	case "kb_get":
		t, err := kb.KBClassText(str("class"))
		if err != nil {
			return textResult("error: " + err.Error())
		}
		return textResult(t)
	case "recipes_get":
		t, err := kb.RecipeText(str("name"))
		if err != nil {
			return textResult("error: " + err.Error())
		}
		return textResult(t)
	case "source_scan":
		return textResult(sourceScanText(str("path")))
	case "fetch":
		url := str("url")
		// SSRF guard: http/https only, and reject hosts resolving to
		// private/loopback/link-local/reserved ranges (defeats DNS rebinding).
		if err := netsec.SSRFSafeURL(url); err != nil {
			return textResult("refused: " + err.Error())
		}
		body, err := fetch.HTTPDo(str("source"), "GET", url, "", 4)
		if err != nil {
			return textResult("error: " + err.Error())
		}
		if len(body) > 512*1024 { // cap response size
			body = body[:512*1024]
		}
		return textResult(string(body))
	default:
		return textResult("unknown tool: " + p.Name)
	}
}

func orAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

// doctorText builds the doctor report as a string (for MCP).
func doctorText(mode, cat string) string {
	plat := tooling.Platform()
	var b []byte
	b = append(b, fmt.Sprintf("platform: %s  mode: %s  category: %s\n", plat, mode, cat)...)
	for _, t := range tooling.ParseRegistry() {
		if !tooling.ModeMatch(t.Modes, mode) || (cat != "all" && cat != t.Category) {
			continue
		}
		status := "absent"
		if _, err := exec.LookPath(t.Name); err == nil {
			status = "present"
		}
		inst := t.Linux
		if plat == "mac" {
			inst = t.Mac
		}
		mark := "present"
		tail := ""
		if status == "absent" {
			mark = "MISSING"
			tail = " -> " + tooling.RenderInstall(inst, plat)
		}
		b = append(b, fmt.Sprintf("  [%s] %s (%s) %s%s\n", t.Category, t.Name, t.Tier, mark, tail)...)
	}
	return string(b)
}

func sourceScanText(path string) string {
	if path == "" {
		path = "."
	}
	if _, err := exec.LookPath("ast-grep"); err != nil {
		return "ast-grep not installed — cannot scan; install per doctor."
	}
	dir, cleanup, err := kb.MaterializeRules()
	if err != nil {
		return "error: " + err.Error()
	}
	defer cleanup()
	out, _ := exec.Command("ast-grep", "scan", "--config", dir+"/sgconfig.yml", path).CombinedOutput()
	if len(out) == 0 {
		return "no findings."
	}
	return string(out)
}
