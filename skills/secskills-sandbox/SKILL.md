---
name: secskills-sandbox
description: "Build and run a target artifact in an isolated Docker sandbox, then discover and test the running instance. Container has no host filesystem mounts, dropped capabilities, and egress restricted to the target. Refuses cleanly if Docker is unavailable — never fakes isolation. Authorization-gated."
disable-model-invocation: true
---

Stand up a buildable/runnable target in isolation, then point discovery and
testing at the running instance. Bridges source mode (have the code) and live
mode (test a running app) without touching production.

## Preconditions

1. **Docker required (D-2).** `command -v docker` and a working daemon. If
   absent, **refuse**: report that sandbox mode needs Docker and stop — do not
   fall back to running the target on the host (that is not isolation).
2. **Authorization gate** (`lib/authz-gate.md`) — the run reaches out during
   testing. Confirm before build/run.
3. `SECSKILLS_WORKDIR` set; `source lib/safety.sh` and `lib/findings-store.sh`.

## Isolation contract (D-2)

Run the target with:
- **No host mounts** — build context copied in, nothing bind-mounted out.
- **Dropped capabilities** — `--cap-drop=ALL`, `--security-opt=no-new-privileges`.
- **Egress restricted** — a dedicated bridge network; the container reaches only
  the instance under test, not the host or the internet, unless a specific test
  requires it (then note it).
- **Ephemeral** — `--rm`; tear down and remove the image after the run.
- **Non-root** where the image allows.

```bash
NET=secskills-sbx-$$; docker network create --internal "$NET"
docker build -t secskills-target:$$ <build-context>
CID=$(docker run -d --rm --name secskills-target-$$ \
  --network "$NET" --cap-drop=ALL --security-opt=no-new-privileges \
  secskills-target:$$)
# resolve the container's address on $NET, then run discover/test against it
```

## Procedure

1. Build the image / start the artifact per its build descriptor
   (Dockerfile, compose, or a documented run command).
2. Resolve the instance address inside the sandbox network.
3. Run the `/secskills-discover` Phase-2 routine against the instance
   (endpoints, headers, tech), then `/secskills-test` classes — same bodies,
   pointed at the sandboxed URL. Scope = the sandbox instance only.
4. Record findings with `emit_finding`.
5. **Teardown always:** stop container, remove image, remove `$NET` — even on
   error (trap EXIT).

## Output

Findings for the running instance in `$SECSKILLS_WORKDIR/findings.json`, plus a
note of the isolation settings used (for the report's methodology section).
Hand to `/secskills-report`.
