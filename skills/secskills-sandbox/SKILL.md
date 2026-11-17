---
name: secskills-sandbox
description: "Build and run a target artifact in an isolated Docker container, then test the running instance. No host mounts, all capabilities dropped, no new privileges, port published to loopback only, container and image removed afterwards. Refuses if Docker is unavailable — never fakes isolation. Authorization-gated."
disable-model-invocation: true
---

Stand up a buildable target in isolation and test it, without touching
production.

## Preconditions

1. **Docker required (D-2).** Without a working Docker, `secskills sandbox`
   refuses. Do not fall back to running the target on the host.
2. **Authorization gate** (`lib/authz-gate.md`) — confirm before build/run.

## Run

```bash
secskills sandbox <build-context> --confirm [--port 8080]
```

The binary builds the image, runs it with `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, no mounts, and `--rm`, publishes the app's
port to `127.0.0.1` only, runs the header and exposure checks against it, then
stops the container and removes the image. It prints the target name for the
report:

```bash
secskills report --render sandbox-<tag>
```

## Deeper testing

The automated pass covers headers and exposed paths. For more, start the
container yourself with the same isolation flags and follow
`thirdparty/redteam-pentest.md` against its loopback address. Record what you
confirm with `secskills findings add --target sandbox-<tag> …`, quoting every
target-derived value in `--evidence-cmd`.

## Output

Findings for the isolated instance, the isolation settings used (for the
report's methodology section), and the report command. Hand to `/secskills-report`.
