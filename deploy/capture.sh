#!/usr/bin/env sh
# secskills exposure mode — CAPTURE phase (target-facing). Runs on a VM near the target
# network. Produces a self-contained workdir of append-only JSONL that you carry
# home and process offline with process.sh. No LLM, no agent, no internet needed
# beyond reaching the targets (and RIPE/whois when resolving an ASN).
#
# Authorization is mandatory. Supply ONE of:
#   - a scope file (.secskills-scope.yml, authorized + unexpired), or
#   - CONFIRM=yes to assert you are authorized for the block.
#
# Usage:
#   CIDR=203.0.113.0/24   CONFIRM=yes ./capture.sh
#   ASN=AS64500           CONFIRM=yes ./capture.sh           # whole ASN (large!)
#   PREFIXES=shard-0.txt  CONFIRM=yes ./capture.sh           # one shard from `secskills plan`
#   CIDR=203.0.113.0/24   CONFIRM=yes INTRUSIVE=yes ./capture.sh   # +default-cred datastore check
#
# Env knobs:
#   BIN        path to the secskills binary        (default: ./secskills)
#   OUT        workdir / output directory          (default: ./capture-<label>)
#   PREFIXES   file of CIDRs (one per line) to sweep into one workdir (sharded fleet)
#   WORKERS    probe concurrency                   (default: 40)
#   INTRUSIVE  yes = run dbcheck default-cred pass  (owner-authorized only)
#   ONLINE     yes = also fetch KEV/EPSS feeds here (else ship/mount a feed cache)
set -eu

BIN="${BIN:-./secskills}"
WORKERS="${WORKERS:-40}"

if [ -n "${PREFIXES:-}" ]; then
  [ -f "$PREFIXES" ] || { echo "error: PREFIXES file not found: $PREFIXES" >&2; exit 2; }
  LABEL=$(basename "$PREFIXES" .txt)
elif [ -n "${CIDR:-}" ]; then
  BLOCK_FLAG="--cidr"; BLOCK_VAL="$CIDR"; LABEL=$(echo "$CIDR" | tr '/.:' '___')
elif [ -n "${ASN:-}" ]; then
  BLOCK_FLAG="--asn"; BLOCK_VAL="$ASN"; LABEL="$ASN"
else
  echo "error: set PREFIXES=<file>, CIDR=<cidr>, or ASN=<AS...>" >&2; exit 2
fi

OUT="${OUT:-./capture-$LABEL}"
export SECSKILLS_WORKDIR="$OUT"      # pin output so the workdir is portable
mkdir -p "$OUT"

CONF=""
[ "${CONFIRM:-}" = "yes" ] && CONF="--confirm"

echo "== capture: ${PREFIXES:-$BLOCK_VAL} -> $OUT =="

# 1. Wide cheap sweep -> observations.jsonl (streamed, resumable after a kill).
#    The store is append-only and content-addressed, so looping a shard file of
#    CIDRs into one workdir is safe: each prefix adds its hits, duplicates dedupe.
if [ -n "${PREFIXES:-}" ]; then
  while IFS= read -r pfx; do
    [ -z "$pfx" ] && continue
    case "$pfx" in \#*) continue ;; esac
    "$BIN" discover --cidr "$pfx" --workers "$WORKERS" $CONF
  done < "$PREFIXES"
else
  "$BIN" discover $BLOCK_FLAG "$BLOCK_VAL" --workers "$WORKERS" $CONF
fi

# 2. Banner enrichment (reconnects to targets; must run here, not offline).
"$BIN" enrich --workdir "$OUT" $CONF || echo "[warn] enrich skipped"

# 3. Read-only exposure pass (exposed .git/.env, dir listings, unauth ES/Redis).
#    Never records credential values — key names only.
"$BIN" leakcheck --workdir "$OUT" $CONF || echo "[warn] leakcheck skipped"

# 4. Datastore default-credential / open-auth posture. Owner-authorized, intrusive.
if [ "${INTRUSIVE:-}" = "yes" ]; then
  "$BIN" dbcheck --workdir "$OUT" --confirm --intrusive-confirm || echo "[warn] dbcheck skipped"
fi

# 5. Optional: fetch feeds on the VM so the kit is fully self-contained.
if [ "${ONLINE:-}" = "yes" ]; then
  "$BIN" feed kev  || true
  "$BIN" feed epss || true
fi

# Package the workdir for transport.
TAR="$OUT.tar.gz"
tar -czf "$TAR" -C "$(dirname "$OUT")" "$(basename "$OUT")"
echo "== done. carry home: $TAR =="
echo "   then: OUT=$(basename "$OUT") ./process.sh   (offline)"
