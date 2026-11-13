# Changelog

## [0.31.0] - 2026-11-13

### Install

```sh
go install github.com/gleicon/secskills/cmd/secskills@v0.31.0
```

Or download a static binary for linux/darwin/windows from this release and check it against
`SHA256SUMS`.

### Changed

- **Standard Go layout.** The CLI lives in `cmd/secskills`, which only parses flags and
  wires commands. The logic moved into packages under `internal/`: `engine`, `exposure`,
  `finding`, `report`, `scope`, `fetch`, `netsec`, `kb`, `tooling`, `mcp`, `workspace`,
  `jsonl` and `textutil`. Embedded assets live in the root `secskills` package. Command
  behaviour and output are unchanged; the golden suite checks this.
- **Version stamping.** Set the version with `-X github.com/gleicon/secskills.Version=…`
  (it was `-X main.version=…`).
- **`make install`** now runs `go install ./cmd/secskills`. `make dist` adds darwin/amd64
  and windows/amd64 builds and writes `SHA256SUMS`.
- **Neutral naming.** The ASN/CIDR pipeline is now "exposure mode" (`SPEC-EXPOSURE.md`,
  `docs/exposure.md`). Examples use documentation ranges (AS64500, 203.0.113.0/24).

### Security

- **Credentialed requests verify TLS.** `test --auth-token/--cookie/--auth-header`
  credentials were sent through the probe client, which skips certificate checks, so an
  attacker on the network path could capture them. Credentialed checks now use a verifying
  client. For self-signed targets, opt in with `--insecure-auth`. **Behaviour change:**
  without the flag, credentialed checks against a host with an invalid certificate now fail.
- **Secret redaction fixed.** Evidence samples showed `password=[REDACTED] hunter2`: the
  label was added but the value stayed. Everything after a credential-like key is now
  masked, and so is a bare `Bearer <token>`.

### Fixed

- Network errors were reported as "HTTP 40" because a default worker count leaked into
  integer formatting.
- `lifecycle reconcile` output and the prefix report's service and CVE tie-breaks were
  printed in random order. Both are now deterministic.
- The binary did not build on Windows.
- Removed unused functions.

### Tests and CI

- Golden CLI suite (`cmd/secskills/cli_golden_test.go`): it builds the binary, runs it in a
  sandbox with no network, and compares the output for every command's help and flags,
  every authorization-gate refusal, MCP, the KB, conformance, measure, selftest, the
  exposure pipeline, scope tokens, and reports, tickets, SARIF, CycloneDX and attestation.
- New unit tests for the SSRF guard, shell quoting, untrusted-text neutralization, JSONL,
  MCP dispatch, SARIF/CycloneDX shape, run-attestation tamper detection, and TLS
  verification for credentialed requests.
- CI: gofmt, vet, race tests, staticcheck, `go install`, and cross-compilation. Pushing a
  `v*` tag builds and publishes the release.
