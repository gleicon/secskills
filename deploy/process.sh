#!/usr/bin/env sh
# secskills network mode — PROCESS phase (offline). Runs anywhere, air-gapped.
# Takes a captured workdir and the vulnerability feeds, adds CVE leads to the
# findings the capture already recorded, saves a run, and writes the report.
# No target traffic. No LLM.
#
# Feeds: needs a feed cache. Either it was shipped with the kit (feed/ dir next
# to this script, point SECSKILLS_FEED at it) or set ONLINE=yes to fetch now.
#
# Usage:
#   OUT=./capture-203_0_113_0_24 ./process.sh
#   OUT=./capture-... BLOCK=203.0.113.0/24 ONLINE=yes ./process.sh
#
# Env knobs:
#   BIN       path to the secskills binary          (default: ./secskills)
#   OUT       the captured workdir                  (required)
#   BLOCK     name for the findings store and report (default: basename of OUT)
#   PRODUCTS  space-separated products to pull NVD ranges for
#             (default: openssh nginx apache)
#   ONLINE    yes = fetch feeds; else use SECSKILLS_FEED / ~/.secskills/feed
set -eu

BIN="${BIN:-./secskills}"
OUT="${OUT:?set OUT=<captured workdir>}"
BLOCK="${BLOCK:-$(basename "$OUT")}"
PRODUCTS="${PRODUCTS:-openssh nginx apache}"
export SECSKILLS_WORKDIR="$OUT"   # every command below reads the carried workdir

# Prefer a feed cache shipped alongside this script.
if [ -z "${SECSKILLS_FEED:-}" ] && [ -d "$(dirname "$0")/feed" ]; then
  export SECSKILLS_FEED="$(cd "$(dirname "$0")/feed" && pwd)"
fi
[ -n "${SECSKILLS_FEED:-}" ] && echo "feed cache: $SECSKILLS_FEED"

echo "== process: $OUT ($BLOCK) =="

if [ "${ONLINE:-}" = "yes" ]; then
  "$BIN" feed kev  || true
  "$BIN" feed epss || true
  for p in $PRODUCTS; do "$BIN" feed nvd --product "$p" || true; done
fi

# 1. Captured leak and datastore results -> findings (needed after merging
#    workdirs from several capture machines; harmless otherwise).
"$BIN" findings import "$BLOCK" --save=false

# 2. Banner versions x NVD ranges -> CVE lead findings (KEV first, EPSS-ranked).
#    Leads that no longer match close as fixed; ones that return reopen.
#    Saves a run under BLOCK for retest, tickets and export.
"$BIN" cvematch "$BLOCK"

# 3. The same report as an app assessment, plus the network inventory.
#    Credential values are never included. Local only; do not publish.
"$BIN" report --render "$BLOCK" --output "$OUT/report.md"

echo "== done. report: $OUT/report.md   tickets: $BIN tickets $BLOCK =="
