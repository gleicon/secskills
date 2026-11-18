# Getting started

## Install

```bash
go install github.com/gleicon/secskills/cmd/secskills@latest
secskills version
```

Requires Go 1.27.4 or newer; an older Go downloads 1.27.4 automatically. Without
Go, download a static binary from the
[latest release](https://github.com/gleicon/secskills/releases/latest) and check
it against `SHA256SUMS` (commands per OS on the
[install page](https://gleicon.github.io/secskills/install.html)). From a
checkout: `make install`.

External security tools are optional. The doctor shows what is present and how
to install the rest:

```bash
secskills doctor                     # every tool, present or missing, with install commands
secskills doctor --mode discover     # only what one mode uses
secskills doctor --category report   # headless browser for PDF reports
```

See [INSTALL.md](../INSTALL.md) for the tool list.

## A first run that touches nothing

```bash
secskills selftest                   # end-to-end pipeline against a local disposable server
secskills kb                         # the embedded OWASP knowledge base
secskills kb injection
secskills recipes access-control     # secure vs vulnerable code for Node, Python, Go
secskills source .                   # static review of a repo you own (needs ast-grep)
```

## Before anything touches a target

Every command that sends traffic refuses until you confirm you are authorized:

```text
$ secskills discover example.com
AUTHORIZATION REQUIRED — discover mode, target: example.com
…
error: authorization not confirmed
```

Pass `--confirm` only with written authorization, or keep an authorized scope
file (`secskills scope --init`, then edit and `secskills scope --validate`).
Details: [SECURITY.md](../SECURITY.md) and the
[safety page](https://gleicon.github.io/secskills/safety.html).

## Where things go

- **Workdir** per target: `<user cache dir>/secskills/<target>`, readable by you
  only (override with `SECSKILLS_WORKDIR`; never a shared path like `/tmp`).
- **Saved runs**: `~/.secskills-findings/<target>/`.
- **Feeds** for network mode: `~/.secskills/feed`.

Treat all three like a credentials store.

## Next

Pick a task in the [guides](guides/README.md):

- [Penetration test of a web app or domain](guides/pentest-web-app.md)
- [Exploring a target's attack surface](guides/explore-attack-surface.md)
- [Scanning a network block (ASN/CIDR)](guides/scan-network-block.md)
- [Reviewing source code](guides/review-source.md)
- [Testing LLM apps](guides/test-llm-apps.md)

Reference: [usage](usage.md) (every command), [reporting](reporting.md),
[architecture](architecture.md).
