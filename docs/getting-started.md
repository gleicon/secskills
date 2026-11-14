# Getting started

## Install

```bash
go install github.com/gleicon/secskills/cmd/secskills@latest
secskills version

# or from a checkout
git clone https://github.com/gleicon/secskills && cd secskills
make install            # go install ./cmd/secskills
```

Requires **Go 1.27.4+** (older Go downloads it automatically). Without Go, download a static binary from the
[latest release](https://github.com/gleicon/secskills/releases/latest) and check it
against `SHA256SUMS` (commands per OS on the
[install page](https://gleicon.github.io/secskills/install.html)).

Runtime security tools are optional — secskills degrades
gracefully and tells you what's missing:

```bash
secskills doctor                 # 64 tools, present/missing, per category
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

Discovery output and evidence go to a private per-target workdir,
`<user cache dir>/secskills/<target>` (override with `SECSKILLS_WORKDIR`; keep it
off shared paths like `/tmp`). Saved runs go to `~/.secskills-findings/<target>/`.

## Guided intake (recommended)

In Claude Code / opencode, run the intake skill instead of steps 1–2 — it
interviews you until nothing is loose and writes the scope file for you:

```
/secskills-intake example.com
```

Install the skills with `claude plugin marketplace add gleicon/secskills` and
`claude plugin install secskills@secskills`.

## Source & sandbox modes

```bash
secskills source ./my-repo          # static ast-grep review, no network, no gate
secskills sandbox ./build-context --confirm   # build+run isolated in Docker, then test
```

## Authenticated testing

Supply credentials to test the authenticated surface; omit them and it's marked
*not available* in the report:

```bash
secskills test example.com --auth-token "$TOKEN"
secskills test example.com --cookie "session=..."
secskills test example.com --auth-token "$A" --auth-token-b "$B"   # BOLA/IDOR differential
```

Credentialed requests verify TLS. Against a self-signed target they fail unless you
add `--insecure-auth`, which exposes those credentials to anyone on the network path.

## Next

- [Usage & commands](usage.md) — every command, profiles, files, environment.
- [Exposure mode](exposure.md) — ASN/CIDR sweeps and offline CVE joins.
- [Reporting & compliance](reporting.md).
- Website: <https://gleicon.github.io/secskills/>
