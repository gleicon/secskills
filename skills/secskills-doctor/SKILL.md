---
name: secskills-doctor
description: "Preflight check for secskills. Verifies every tool the package can use — the skills tier (curl/dig/jq/python3/git, used by these skills) and optional power tools (subfinder, httpx, nuclei, katana, dalfox, sslscan, osv-scanner, trufflehog, ast-grep, docker) — reports what is present or missing per mode, and prints the exact install command for macOS (brew) or Ubuntu (apt/go/cargo). Read-only; installs nothing."
---

Run the environment check before an assessment so a mode does not stop halfway
on a missing tool. Read-only — it reports and prints install commands, never
installs anything itself.

## Run it

```bash
secskills doctor                     # full report — 64 tools, 19 categories
secskills doctor --mode source       # only tools that mode uses
secskills doctor --mode live         # discover + test tools
secskills doctor --category osint     # one category (osint/dns/http/port/vuln/cve/...)
secskills doctor --tools nuclei,httpx # only named tools
secskills doctor --quiet             # only what is missing
secskills doctor --json              # machine-readable
secskills doctor --list-categories
```

Exit code `1` only when the selected mode cannot run: `--mode sandbox` without
docker. Otherwise `0`, with every ✗ listed as optional.

## Tiers (D-1)

- **Skills** (`curl`, `dig`, `jq`, `python3`, `git`): used by these skills and the
  `lib/` shell helpers. The secskills binary does not need them.
- **Power** (optional): each widens coverage for one mode. Absent → the mode
  degrades gracefully and notes the gap; never a hard stop. `docker` is required
  **only** for sandbox mode.

## Per-mode tool needs

| Mode | Skills tier | Power tools |
|------|----------|-------------|
| source | curl, jq, python3 | ast-grep (engine), osv-scanner |
| discover | curl, dig, jq | subfinder, amass, httpx |
| test | curl, jq, python3 | httpx, nuclei, katana, dalfox, sslscan, osv-scanner, trufflehog |
| sandbox | (above) | docker (**required**), + test tools |

## Installing

The doctor prints the platform-correct command per missing tool. For the full
matrix and toolchain setup (Go/Rust for the projectdiscovery/dalfox/ast-grep
tools), see `INSTALL.md`. After installing Go/cargo tools on Linux, ensure
`$(go env GOPATH)/bin` and `~/.cargo/bin` are on `PATH`, then re-run the doctor.

## When to run

- First install of secskills.
- Before a live or sandbox engagement (confirm scanners present).
- After a `command not found` mid-run — `secskills doctor --quiet` names the gap.
