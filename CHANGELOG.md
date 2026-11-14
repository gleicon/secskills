# Changelog

## [0.32.0] - 2026-11-13

### Changed

- **`secskills doctor` exit code.** It exits `1` only when the selected mode
  can't run (`--mode sandbox` without docker). It used to fail whenever
  `curl`, `dig`, `jq`, `python3` or `git` was missing, though the binary uses none
  of them. Those tools are now the `skills` tier, used by the agent skills and
  `lib/` helpers. `tools/doctor.sh` behaves the same way.
- `secskills help` lists the real MCP tool set, links to the website, and says
  where the workdir lives.
- The docs describe what exists, not what's planned. Removed `roadmap.md`,
  `PROGRESS.md` (a build log of "next" notes) and `IMPORT.md` (a planning map).
  `SPEC-EXPOSURE.md` is now a design record of what's built: unbuilt feed sources,
  LLM extraction, MCP finding tools, phases, open questions and the watchlist are
  gone; requirement and decision IDs cited in code are kept. Code comments no
  longer promise future work.
- README, `INSTALL.md`, `docs/usage.md`, `docs/getting-started.md`, the coverage
  matrix, `AGENTS.md`, `ADAPTERS.md`, the doctor and discover skills, and the
  website now match the CLI: release binaries, plugin marketplace, exposure-mode
  commands, test profiles, where flags can go, files and environment.

### Fixed

- `docs/getting-started.md` showed `sandbox` without the required `--confirm`.
- The coverage matrix said CVSS was a band only; full CVSS 3.1 vectors exist.

## [0.31.2] - 2026-11-13

### Added

- Website at <https://gleicon.github.io/secskills/> covering install (go install, checksummed
  binaries, agents), usage, common cases, and the safety model. Built from `site/` with
  `python3 site/build.py`, no dependencies, and deployed by the pages workflow.
- Claude Code marketplace manifest. Install with
  `claude plugin marketplace add gleicon/secskills` and then
  `claude plugin install secskills@secskills`.
- `secskills help` now lists the 15 exposure-mode commands. They worked before but were not
  listed.

### Fixed

- `.claude-plugin/plugin.json` failed plugin validation because `author` must be an object.
- Plugin manifest versions were stuck at 0.3.0. The release workflow now fails if they don't
  match the tag.

### Security

- Workdirs moved out of shared temp space. They were a predictable
  `$TMPDIR/secskills-<target>` path created `0755`. On a shared host another user could
  pre-create that path, or a symlink, and read or redirect the evidence. The default is now
  `<user cache dir>/secskills/<target>` (`~/.cache` on Linux, `~/Library/Caches` on macOS),
  created `0700`. A workdir that is a symlink, isn't a directory, or is owned by another
  user is refused, and a looser mode is tightened to `0700`. `scope.txt` is written `0600`.
  **Behaviour change:** existing workdirs under `$TMPDIR` aren't migrated. Retests and
  reports that need one should set `SECSKILLS_WORKDIR` to the old path.
- `SECURITY.md`: reports stay private and a person handles each one. There is no automated
  intake.

### Maintenance

- Dependabot for Go modules and GitHub Actions.
- CI checks that the website builds.

## [0.31.1] - 2026-11-13

### Fixed

- `TestMPTCPCapableAgainstPlainListener` failed on Linux. Since Go 1.24, `net.Listen`
  opens MPTCP listeners by default there, so the test's "plain" listener was MPTCP and
  the probe was right to say so. The test now opts out of MPTCP explicitly. The probe
  itself is unchanged. This failure blocked the v0.31.0 release build, so v0.31.0 has a
  tag but no binaries; use 0.31.1.

### Install

```sh
go install github.com/gleicon/secskills/cmd/secskills@v0.31.1
```

Everything else is as listed under 0.31.0.

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
