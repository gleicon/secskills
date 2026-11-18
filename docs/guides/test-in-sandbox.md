# Testing a build in a sandbox

Build an artifact, run it in an isolated container, and test the running
instance — without touching production. Needs Docker.

## Before you start

- Docker running locally. Without it, `sandbox` refuses rather than running the
  target on your machine.
- A build context: a directory with a `Dockerfile`.
- Authorization to run and test the code (it is still a target).

## Run

```bash
secskills sandbox ./build-context --confirm --port 8080
```

`--port` is the port the app listens on inside the container. secskills:

1. builds the image;
2. runs it with `--cap-drop=ALL`, `--security-opt=no-new-privileges`, no host
   mounts, and `--rm`, publishing the port on `127.0.0.1` only;
3. runs the header and exposure checks against it;
4. stops the container and removes the image, even on error.

It prints the target name for the report:

```bash
secskills report --render sandbox-<tag>
```

## Going deeper

The automated pass covers headers and exposed paths. For more, start the
container yourself with the same isolation flags and work through
`thirdparty/redteam-pentest.md` against `http://127.0.0.1:<port>`. Record what
you confirm:

```bash
secskills findings add --target sandbox-<tag> --id SBX-MAN-01 --title "…" \
  --host "http://127.0.0.1:8080/admin" --severity HIGH --status manual
```

Pair it with a [source review](review-source.md) of the same code: sandbox
findings show what is reachable, source findings show why.
