#!/usr/bin/env sh
# secskills exposure mode — VPS setup. Installs the binary, loads the vulnerability feed
# cache ONCE, and writes an env file the capture/process scripts source. Run it
# on the box that will fetch the feed (and, for a single-box setup, also capture).
# Idempotent: re-run it to refresh the feed.
#
# Usage:
#   ./setup.sh                       # install from ./secskills or build, fetch feeds
#   PREFIX=/opt/secskills ./setup.sh # install under a chosen root
#   PRODUCTS="openssh nginx apache postgresql" ./setup.sh
#   OFFLINE=yes ./setup.sh           # skip fetching (feed already present)
#
# Env knobs:
#   PREFIX    install root                    (default: /opt/secskills, falls back to ~/.secskills if not writable)
#   BIN_SRC   path to a prebuilt binary        (default: ./secskills, else build with go)
#   PRODUCTS  NVD products to pull ranges for  (default: openssh nginx apache)
#   OFFLINE   yes = do not fetch feeds
set -eu

PREFIX="${PREFIX:-/opt/secskills}"
PRODUCTS="${PRODUCTS:-openssh nginx apache}"

# Fall back to a home-dir prefix if the chosen root is not writable.
if ! mkdir -p "$PREFIX/bin" "$PREFIX/feed" 2>/dev/null; then
  PREFIX="$HOME/.secskills-vps"
  echo "note: using $PREFIX (default root not writable)"
  mkdir -p "$PREFIX/bin" "$PREFIX/feed"
fi
BIN="$PREFIX/bin/secskills"
FEED_DIR="$PREFIX/feed"

# 1. Install the binary: a prebuilt one, or build from source if go is present.
if [ -x "${BIN_SRC:-}" ]; then
  cp "$BIN_SRC" "$BIN"
elif [ -x "./secskills" ]; then
  cp ./secskills "$BIN"
elif command -v secskills >/dev/null 2>&1; then
  cp "$(command -v secskills)" "$BIN"
elif command -v go >/dev/null 2>&1 && [ -f go.mod ]; then
  echo "building from source (CGO off, static)…"
  CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/secskills
else
  echo "error: no binary found and no go toolchain to build one." >&2
  echo "       provide BIN_SRC=/path/to/secskills, or run from a checkout with 'go'." >&2
  exit 2
fi
chmod +x "$BIN"
echo "installed: $BIN ($("$BIN" version 2>/dev/null | head -1 || echo unknown))"

# Place the runner scripts next to the binary if they are alongside this setup.
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for s in capture.sh process.sh; do
  [ -f "$SELF_DIR/$s" ] && cp "$SELF_DIR/$s" "$PREFIX/$s" && chmod +x "$PREFIX/$s"
done

# 2. Load the feed cache ONCE into $FEED_DIR. Every VM mounts this read-only;
#    none of them fetch feeds themselves.
export SECSKILLS_FEED="$FEED_DIR"
if [ "${OFFLINE:-}" != "yes" ]; then
  echo "loading feeds -> $FEED_DIR"
  "$BIN" feed kev  || echo "[warn] KEV fetch failed"
  "$BIN" feed epss || echo "[warn] EPSS fetch failed"
  for p in $PRODUCTS; do
    "$BIN" feed nvd --product "$p" || echo "[warn] NVD $p fetch failed"
  done
else
  echo "OFFLINE: skipping feed fetch (expecting $FEED_DIR already populated)"
fi
echo "feed cache: $FEED_DIR ($(ls -1 "$FEED_DIR" 2>/dev/null | wc -l | tr -d ' ') files)"

# 3. Write a sourceable env file so capture.sh/process.sh pick up the shared feed.
ENV_FILE="$PREFIX/secskills.env"
cat > "$ENV_FILE" <<EOF
# source this before capture.sh / process.sh
export PATH="$PREFIX/bin:\$PATH"
export SECSKILLS_FEED="$FEED_DIR"
export BIN="$BIN"
EOF
echo "env file: $ENV_FILE"

cat <<EOF

ready. next:
  . $ENV_FILE
  # single box:
  CIDR=203.0.113.0/24 CONFIRM=yes $PREFIX/capture.sh
  OUT=./capture-203_0_113_0_24 $PREFIX/process.sh
  # fleet: share $FEED_DIR read-only to each VM (SECSKILLS_FEED=$FEED_DIR), then:
  secskills plan --asn AS64500 --shards 8 --out ./plan
  SECSKILLS_FEED=$FEED_DIR PREFIXES=plan/shard-0.txt CONFIRM=yes $PREFIX/capture.sh
EOF
