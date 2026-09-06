# Getting started

## Install

```bash
git clone <repo> secskills && cd secskills
make install            # go build → $GOPATH/bin/secskills
secskills version
```

Requires **Go 1.26+**. Runtime security tools are optional — secskills degrades
gracefully and tells you what's missing:

```bash
secskills doctor                 # ~63 tools, present/missing, per category
secskills doctor --mode discover # only what discover uses
secskills doctor --category report   # is a headless browser present (PDF)?
```

Install missing tools with the command the doctor prints (brew / apt / go / cargo
/ pipx). See [INSTALL.md](../INSTALL.md).

## Your first engagement (live target)

**Only test targets you are authorized to test.**

```bash
# 1. Research — passive OSINT, no traffic to the target
secskills profile example.com --output ENGAGEMENT-profile.md

# 2. Scope — write the engagement file the gate honors
secskills scope --init
#    edit .secskills-scope.yml: authorized: true, targets:, out_of_scope:, expires:
secskills scope --validate

# 3. Discover — subdomains → resolve → live hosts (+ Shodan if a key is set)
secskills discover example.com

# 4. Test — headers, TLS, exposure, CVEs; --deep adds nuclei/sslscan/screenshots
secskills test example.com --deep

# 5. Report — Markdown, HTML, or professional PDF (SOC2/ISO/PCI mapped)
secskills report --pdf example.com --output example_report.pdf
```

With an authorized `.secskills-scope.yml`, steps 3–4 need no `--confirm`. Without
it, add `--confirm` (and confirm you hold written authorization).

## Guided intake (recommended)

In Claude Code / opencode, run the intake skill instead of steps 1–2 — it
interviews you until nothing is loose and writes the scope file for you:

```
/secskills-intake example.com
```

## Source & sandbox modes

```bash
secskills source ./my-repo          # static ast-grep review, no network, no gate
secskills sandbox ./build-context   # build+run isolated in Docker, then test
```

## Authenticated testing

Supply credentials to test the authenticated surface; omit them and it's marked
*not available* in the report:

```bash
secskills test example.com --auth-token "$TOKEN"
secskills test example.com --cookie "session=..."
```
