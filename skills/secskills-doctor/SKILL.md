---
name: secskills-doctor
description: "Preflight check for secskills. Verifies every tool the package can use — baseline (curl/dig/jq/python3/git) and optional power tools (subfinder, httpx, nuclei, katana, dalfox, sslscan, osv-scanner, trufflehog, ast-grep, docker) — reports what is present or missing per mode, and prints the exact install command for macOS (brew) or Ubuntu (apt/go/cargo). Read-only; installs nothing."
---

Run the environment check before an assessment so a mode does not stop halfway
on a missing tool. Read-only — it reports and prints install commands, never
installs anything itself.

## Run it

```bash
tools/doctor.sh                     # full report — ~60 tools, 17 categories
tools/doctor.sh --mode source       # only tools that mode uses
tools/doctor.sh --mode live         # discover + test tools
tools/doctor.sh --category osint     # one category (osint/dns/http/port/vuln/cve/...)
tools/doctor.sh --tools nuclei,httpx # only named tools
tools/doctor.sh --quiet             # only what is missing
tools/doctor.sh --json              # machine-readable
tools/doctor.sh --list-categories
```

Exit code `0` = all baseline tools present (secskills can run). Exit `1` = a
baseline tool is missing.

## Tiers (D-1)

- **Baseline** (required): `curl`, `dig`, `jq`, `python3`, `git`. Missing one
  blocks the run.
- **Power** (optional): each widens coverage for one mode. Absent → the mode
  degrades gracefully and notes the gap; never a hard stop. `docker` is required
  **only** for sandbox mode.

## Per-mode tool needs

| Mode | Baseline | Power tools |
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
- After a `command not found` mid-run — `tools/doctor.sh --quiet` names the gap.
