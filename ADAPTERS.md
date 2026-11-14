# Multi-agent adapters

secskills works on three agent surfaces off the **same binary**. Logic lives in
`secskills`; each adapter is thin.

## 1. Claude Code

Two ways, both included:

- **Skills / plugin:** the `skills/*/SKILL.md` + `.claude-plugin/` in this repo,
  published as a marketplace. Install the binary first
  (`go install github.com/gleicon/secskills/cmd/secskills@latest`), then:
  ```bash
  claude plugin marketplace add gleicon/secskills
  claude plugin install secskills@secskills
  ```
  Skill bodies call the binary (`secskills <cmd>`) and read `lib/*.md` for methodology.
- **MCP server:** register the stdio server so tools appear natively:
  ```bash
  claude mcp add secskills -- secskills mcp
  ```
  or in `.mcp.json`:
  ```json
  { "mcpServers": { "secskills": { "command": "secskills", "args": ["mcp"] } } }
  ```

## 2. opencode

- **Instructions:** `AGENTS.md` (opencode reads it automatically).
- **Command:** `.opencode/command/secskills.md` → `/secskills <target> <intent>`.
- **MCP:** in `opencode.json`:
  ```json
  {
    "$schema": "https://opencode.ai/config.json",
    "mcp": {
      "secskills": { "type": "local", "command": ["secskills", "mcp"], "enabled": true }
    }
  }
  ```

## 3. Any MCP client

`secskills mcp` is JSON-RPC 2.0 over stdio (newline-delimited), protocol
`2024-11-05`. Handshake + tools:

```bash
printf '%s\n%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
 | secskills mcp
```

Exposed tools (read-only / non-target-touching by default): `doctor`, `kb_list`,
`kb_get`, `recipes_get`, `source_scan`, `fetch`. Live `discover`/`test` stay behind the CLI's
`--confirm` gate and are intentionally **not** auto-exposed over MCP — an MCP
client would run them unattended, which must not happen without the gate.

## Why a binary, not shell

One static artifact (mac/linux/arm), no bash-portability tax (`shasum` vs
`sha256sum`, `timeout` vs `gtimeout`, BSD vs GNU), real tests, embedded KB +
rules (`go:embed`) so it runs offline. External pentest tools stay external —
the binary shells out to them, never reimplements them. The shell `lib/*.sh`
remain as a readable reference and a fallback.
