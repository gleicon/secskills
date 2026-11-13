package main

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/gleicon/secskills/internal/mcp"
)

// Minimal MCP stdio server (JSON-RPC 2.0, newline-delimited) — zero deps, so any
// MCP-capable agent can call secskills. Exposes read-only, non-target-touching
// tools by default (doctor, kb, source scan); fetch is throttled. Live discover/
// test stay behind the CLI's --confirm gate and are not auto-exposed here.
func cmdMCP(_ []string) error {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req mcp.RPCReq
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		resp, notify := mcp.DispatchMCP(req)
		if notify {
			continue // no response for notifications
		}
		b, _ := json.Marshal(resp)
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
	}
	return in.Err()
}
