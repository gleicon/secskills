#!/usr/bin/env bash
# secskills — OWASP Cheat Sheet Series ingestion / refresh (D-8, FR-9, FR-10).
#
# Refreshes the vendored KB snapshot against upstream and reports which files
# changed. Network is used ONLY here, at ingestion time — never at skill invoke
# (NFR-3). Run manually to update; the KB works offline in between.
#
# Usage:
#   tools/ingest.sh [--check] [--ref <git-ref>]
#     --check   fetch + diff only, write nothing (report drift)
#     --ref     upstream ref/tag/branch to pin (default: master)
#
# Requires: git, curl. Optional: pandoc (better HTML→md if pulling rendered site).

set -euo pipefail

REPO="https://github.com/OWASP/CheatSheetSeries.git"
REF="master"
CHECK_ONLY=0
VENDOR=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KB="$ROOT/kb"
SNAP_DIR="${TMPDIR:-/tmp}/secskills-cheatsheets"

while [ $# -gt 0 ]; do
  case "$1" in
    --check)  CHECK_ONLY=1; shift ;;
    --vendor) VENDOR=1; shift ;;
    --ref)    REF="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v git >/dev/null || { echo "git required"; exit 1; }

# validate REF: allowlist only, reject leading dash (argument injection)
case "$REF" in
  -*) echo "invalid --ref (leading dash)"; exit 2 ;;
esac
if ! printf '%s' "$REF" | grep -qE '^[A-Za-z0-9._/-]+$'; then
  echo "invalid --ref: allowed chars are A-Za-z0-9._/-"; exit 2
fi

echo "== secskills ingest =="
echo "upstream: $REPO @ $REF"
echo "snapshot: $SNAP_DIR"

# 1. Fetch upstream cheat sheets (sparse — only the markdown source dir).
if [ -d "$SNAP_DIR/.git" ]; then
  git -C "$SNAP_DIR" fetch --depth 1 origin "$REF"
  git -C "$SNAP_DIR" checkout -q "origin/$REF" 2>/dev/null || git -C "$SNAP_DIR" checkout -q "$REF"
else
  rm -rf "$SNAP_DIR"
  git clone --depth 1 --branch "$REF" --filter=blob:none --sparse "$REPO" "$SNAP_DIR"
  git -C "$SNAP_DIR" sparse-checkout set cheatsheets
fi

UPSTREAM_REV="$(git -C "$SNAP_DIR" rev-parse --short HEAD)"
echo "upstream rev: $UPSTREAM_REV"
SRC="$SNAP_DIR/cheatsheets"
[ -d "$SRC" ] || { echo "no cheatsheets/ in upstream checkout"; exit 1; }

# 2. For each KB class, report which of its bundled cheat sheets drifted upstream.
#    (This snapshot's KB entries are curated summaries — refresh is advisory:
#     it surfaces upstream changes to the summarized sheets so an editor can
#     update kb/<class>/README.md, and records the new snapshot rev.)
CHANGED=0
echo ""
echo "== drift report (bundled cheat sheets vs upstream $UPSTREAM_REV) =="
for classfile in "$KB"/*/README.md "$KB"/top10/README.md; do
  [ -f "$classfile" ] || continue
  class="$(basename "$(dirname "$classfile")")"
  # pull each bundled sheet's slug from the provenance URLs
  grep -oE 'cheatsheets/[A-Za-z0-9_]+_Cheat_Sheet\.html' "$classfile" 2>/dev/null \
    | sed -E 's#cheatsheets/##; s#\.html$#.md#' | sort -u \
  | while IFS= read -r sheet; do
      up="$SRC/$sheet"
      if [ ! -f "$up" ]; then
        printf '  [%s] MISSING upstream: %s (renamed/removed?)\n' "$class" "$sheet"
      else
        # hash upstream sheet; compare to recorded hash sidecar
        h="$(shasum -a 256 "$up" | cut -c1-12)"
        sidecar="$KB/$class/.snapshot-hashes"
        prev="$(grep -F " $sheet" "$sidecar" 2>/dev/null | awk '{print $1}' || true)"
        if [ "$h" != "$prev" ]; then
          printf '  [%s] CHANGED upstream: %s (%s -> %s)\n' "$class" "$sheet" "${prev:-none}" "$h"
          [ "$CHECK_ONLY" -eq 0 ] && { touch "$sidecar"; grep -vF " $sheet" "$sidecar" > "$sidecar.tmp" 2>/dev/null || true; mv -f "$sidecar.tmp" "$sidecar" 2>/dev/null || true; echo "$h $sheet" >> "$sidecar"; }
        fi
        # --vendor: copy the full upstream sheet into kb/<class>/vendored/ with a
        # provenance header. Offline-usable afterwards; the curated README stays
        # the primary entry, vendored/ holds the verbatim source (CC BY-SA).
        if [ "$VENDOR" -eq 1 ] && [ -f "$up" ]; then
          vdir="$KB/$class/vendored"; mkdir -p "$vdir"
          slug="$(basename "$sheet")"
          {
            printf -- '---\n'
            printf 'vendored_from: OWASP Cheat Sheet Series\n'
            printf 'source_url: https://cheatsheetseries.owasp.org/cheatsheets/%s\n' "${slug%.md}.html"
            printf 'upstream_rev: %s\n' "$UPSTREAM_REV"
            printf 'license: CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/)\n'
            printf 'vendored_at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf -- '---\n\n'
            cat "$up"
          } > "$vdir/$slug"
          printf '  [%s] vendored: %s\n' "$class" "$slug"
        fi
      fi
    done
done

if [ "$CHECK_ONLY" -eq 1 ]; then
  echo ""
  echo "check-only: no files written. Review drift above; re-run without --check to record."
  exit 0
fi

# 3. Record the snapshot rev for provenance.
echo "$UPSTREAM_REV  $(date -u +%Y-%m-%dT%H:%M:%SZ)  ref=$REF" >> "$ROOT/kb/.snapshot-log"
echo ""
echo "recorded snapshot rev $UPSTREAM_REV to kb/.snapshot-log"
echo "Next: edit kb/<class>/README.md for any CHANGED sheet, then commit."
