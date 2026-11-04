#!/usr/bin/env sh
# secskills exposure mode — PROCESS phase (offline joins). Runs anywhere, air-gapped. Takes
# a captured workdir and the vulnerability feeds, joins them, and writes the
# administrator report. No target traffic. No LLM.
#
# Feeds: needs a feed cache. Either it was shipped with the kit (feed/ dir next
# to this script, point SECSKILLS_FEED at it) or set ONLINE=yes to fetch now.
#
# Usage:
#   OUT=./capture-203_0_113_0_24 ./process.sh
#   OUT=./capture-... ONLINE=yes ./process.sh        # fetch NVD/KEV/EPSS now
#
# Env knobs:
#   BIN       path to the secskills binary          (default: ./secskills)
#   OUT       the captured workdir                  (required)
#   PRODUCTS  space-separated products to pull NVD ranges for
#             (default: openssh nginx apache)
#   ONLINE    yes = fetch feeds; else use SECSKILLS_FEED / ~/.secskills/feed
set -eu

BIN="${BIN:-./secskills}"
OUT="${OUT:?set OUT=<captured workdir>}"
PRODUCTS="${PRODUCTS:-openssh nginx apache}"

# Prefer a feed cache shipped alongside this script.
if [ -z "${SECSKILLS_FEED:-}" ] && [ -d "$(dirname "$0")/feed" ]; then
  export SECSKILLS_FEED="$(cd "$(dirname "$0")/feed" && pwd)"
fi
[ -n "${SECSKILLS_FEED:-}" ] && echo "feed cache: $SECSKILLS_FEED"

echo "== process: $OUT =="

if [ "${ONLINE:-}" = "yes" ]; then
  "$BIN" feed kev  || true
  "$BIN" feed epss || true
  for p in $PRODUCTS; do "$BIN" feed nvd --product "$p" || true; done
fi

# 1. Join enriched observations x NVD ranges -> version-inferred CVE candidates,
#    KEV-escalated, EPSS-weighted.
"$BIN" cvematch --workdir "$OUT"

# 2. Lifecycle reconcile: diff this snapshot vs the stored findings. Disappeared
#    candidate -> auto fixed (re-verified); reappeared -> regressed.
"$BIN" lifecycle reconcile --workdir "$OUT" || echo "[warn] lifecycle skipped"

# 3. Administrator report (Markdown). Credential values never included. 0600,
#    local only — share with the asset owner's admins, do not publish.
"$BIN" prefix-report --workdir "$OUT"

echo "== done. report in $OUT =="
