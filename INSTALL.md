# Installing secskills tools

Install the binary first (`go install github.com/gleicon/secskills/cmd/secskills@latest`,
or a release binary — see the [install page](https://gleicon.github.io/secskills/install.html)).
This file covers the **external tools** it can drive.

secskills follows graceful degradation (D-1): every tool is optional except
`docker` for sandbox mode. Tools in the **skills** tier are used by the agent
skills and the `lib/` shell helpers, not by the binary. `secskills doctor` exits
`1` only when the selected mode cannot run (`--mode sandbox` without docker). Run
the doctor first — it prints the exact install command per missing tool for your
platform:

```bash
secskills doctor             # what is present/missing, per mode
secskills doctor --quiet     # only the gaps
```

`tools/doctor.sh` is the equivalent shell reference with the same flags.

## Skills tier (agent skills and `lib/` helpers)

| Tool | Purpose | macOS (brew) | Ubuntu |
|------|---------|--------------|--------|
| `curl` | HTTP/API requests | `brew install curl` | `sudo apt-get install -y curl` |
| `dig` | DNS queries | `brew install bind` | `sudo apt-get install -y dnsutils` |
| `jq` | JSON parsing | `brew install jq` | `sudo apt-get install -y jq` |
| `python3` | OSV queries, processing | `brew install python3` | `sudo apt-get install -y python3` |
| `git` | KB refresh, findings backup | `brew install git` | `sudo apt-get install -y git` |

macOS bundles `curl`/`dig`; Ubuntu bundles `python3`/`curl` on most images.

## Token optimizer (strongly recommended)

`tldt` compresses OSINT/recon output, scrubs PII/secrets before reporting, and
detects prompt injection in target output. OSINT is the biggest token sink in an
assessment — install it.

| Tool | macOS | Ubuntu |
|------|-------|--------|
| `tldt` | `pipx install tldt` | `go install github.com/gleicon/tldt@latest` |

## Full arsenal

The doctor is the source of truth for **all 64 tools** across 19 categories
(core, osint, dns, http, port, vuln, cve, secrets, content, params, tls, cloud,
exploit, oob, source, sandbox, report, mobile, optimizer). List and
install-command per platform:

```bash
secskills doctor                      # everything, present/missing + install cmd
secskills doctor --category osint     # one category
secskills doctor --mode discover      # one mode's tools
secskills doctor --list-categories
```

The tables below are the common highlights; run the doctor for the rest.

## Power tools (optional, per mode)

### Toolchains first (Ubuntu only)

The projectdiscovery tools, `dalfox`, and `osv-scanner` install via **Go**;
`ast-grep` via **Rust/cargo**. On macOS `brew` handles all of them — no
toolchain needed.

```bash
# Ubuntu — Go
sudo apt-get install -y golang-go
# ensure Go-installed binaries are on PATH:
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc && source ~/.bashrc

# Ubuntu — Rust (for ast-grep)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Tools

| Tool | Mode | macOS (brew) | Ubuntu |
|------|------|--------------|--------|
| `subfinder` | discover | `brew install subfinder` | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | discover | `brew install amass` | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| `httpx` | discover, test | `brew install httpx` | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `nuclei` | test | `brew install nuclei` | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `katana` | test | `brew install katana` | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| `dalfox` | test | `brew install dalfox` | `go install github.com/hahwul/dalfox/v2@latest` |
| `sslscan` | test | `brew install sslscan` | `sudo apt-get install -y sslscan` |
| `osv-scanner` | test, source | `brew install osv-scanner` | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` |
| `trufflehog` | test | `brew install trufflehog` | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \| sh -s -- -b /usr/local/bin` |
| `ast-grep` | source (engine) | `brew install ast-grep` | `cargo install ast-grep --locked` |
| `docker` | sandbox (**required for that mode**) | `brew install --cask docker` | `sudo apt-get install -y docker.io` |
| `shodan` | osint (internet asset search) | `brew install shodan` | `pipx install shodan` |
| `fofax` | osint (FOFA asset search) | `go install github.com/xiecat/fofax/cmd/fofax@latest` | `go install github.com/xiecat/fofax/cmd/fofax@latest` |

## OSINT API keys

Keyed sources run **only when a credential resolves**; without one they are
skipped with a note, never blocking the scan (see `lib/osint-sources.md`).
Resolution order per source: session env var → tool config → skip.

```bash
# Shodan — any one of:
shodan init <API_KEY>                 # systemwide ~/.shodan/api_key (once)
export SHODAN_API_KEY=<API_KEY>       # session only
# raw API needs no CLI: curl "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_API_KEY"

# FOFA
export FOFA_EMAIL=<email> FOFA_KEY=<key>     # or ~/.config/fofax/fofax.yaml

# GitHub (github-subdomains, gau code search)
export GITHUB_TOKEN=<token>                  # or `gh auth login`

# Others: PDCP_API_KEY (chaos), URLSCAN_API_KEY, CENSYS_API_ID/SECRET, VT_API_KEY
```

Never commit keys or let them appear in reports/artifacts.

### httpx name collision (macOS)

Python ships an `httpx`. secskills needs projectdiscovery's. Verify:

```bash
httpx --version | grep -i projectdiscovery \
  || echo "wrong httpx on PATH — use $(brew --prefix)/Cellar/httpx/*/bin/httpx"
```

## By mode — minimum to be useful

- **source:** `ast-grep` (the engine) — without it, source mode falls back to a
  grep-assisted read. `osv-scanner` adds dependency-CVE coverage.
- **discover:** `subfinder` + `httpx`. Without them, falls back to `curl` +
  crt.sh + `dig`.
- **test:** `nuclei`, `katana`, `dalfox`, `sslscan`, `osv-scanner`, `trufflehog`.
  Each maps to specific OWASP classes; absent ones skip those checks with a note.
- **sandbox:** `docker` is mandatory — the mode refuses without it (D-2).

## After installing

Re-run `secskills doctor` to confirm. On Linux, if a freshly-installed Go/cargo
tool is "missing", `$(go env GOPATH)/bin` or `~/.cargo/bin` is not on `PATH`.

## Report rendering (PDF)

| Tool | Mode | macOS | Ubuntu |
|------|------|-------|--------|
| `chrome` (headless browser) | report `--pdf` + deep screenshots | `brew install --cask google-chrome` | `sudo apt-get install -y chromium-browser` |

`secskills report --pdf` renders via headless Chrome/Chromium. If none is found it
still writes the HTML report and tells you to use the browser's Print-to-PDF.
`secskills doctor --category report` shows whether a headless browser is detected
(macOS app bundles are detected too, not just PATH).
