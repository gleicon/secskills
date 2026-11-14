#!/usr/bin/env bash
# secskills doctor — check every tool secskills can use, grouped by category and
# mode, and print the exact install command for macOS (brew) or Ubuntu
# (apt/go/cargo/pipx/npm/script). Read-only — reports and prints commands, never
# installs.
#
# Usage:
#   tools/doctor.sh                       # full report
#   tools/doctor.sh --mode source|discover|test|sandbox|live|all
#   tools/doctor.sh --category osint|dns|http|port|vuln|cve|secrets|content|params|tls|cloud|exploit|oob|source|optimizer
#   tools/doctor.sh --tools nuclei,httpx  # only these
#   tools/doctor.sh --json | --quiet | --list-categories
#
# Exit: 0 unless the selected mode cannot run (sandbox without docker).
# Design (D-1): every other tool is optional — absent ones are reported with an
# install command, never a hard stop. Tier "skills" is used by the agent skills
# and lib/ helpers, not by the secskills binary.

set -uo pipefail

MODE="all"; CAT="all"; TOOLS=""; FORMAT="text"; QUIET=0; LISTCAT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --category) CAT="$2"; shift 2 ;;
    --tools) TOOLS=",$2,"; shift 2 ;;
    --json) FORMAT="json"; shift ;;
    --quiet) QUIET=1; shift ;;
    --list-categories) LISTCAT=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then PLAT="mac"; elif [ "$OS" = "Linux" ]; then PLAT="linux"; else PLAT="other"; fi

# Registry: name | tier | category | modes | mac-install | linux-install | note
# Install fields use prefixes rendered by render_install():
#   go:<mod>  cargo:<crate>  pipx:<pkg>  npm:<pkg>  cask:<name>
#   script:<key>  (curl|sh installers)   plain name -> brew / apt
REGISTRY="$(cat "$(dirname "$0")/registry.tsv")"

if [ "$LISTCAT" -eq 1 ]; then
  echo "categories:"; printf '%s\n' "$REGISTRY" | awk -F'\t' 'NF{print $3}' | sort -u | sed 's/^/  /'; exit 0
fi

mode_match() { local tm="$1" req="$2"
  [ "$req" = "all" ] && return 0
  case ",$tm," in *",all,"*) return 0 ;; esac
  if [ "$req" = "live" ]; then case ",$tm," in *",discover,"*|*",test,"*|*",live,"*) return 0 ;; esac; fi
  case ",$tm," in *",$req,"*) return 0 ;; esac; return 1; }

render_install() { local spec="$1"
  case "$spec" in
    go:*)     printf 'go install -v %s' "${spec#go:}" ;;
    cargo:*)  printf 'cargo install %s --locked' "${spec#cargo:}" ;;
    pipx:*)   printf 'pipx install %s' "${spec#pipx:}" ;;
    npm:*)    printf 'npm install -g %s' "${spec#npm:}" ;;
    cask:*)   printf 'brew install --cask %s' "${spec#cask:}" ;;
    git:*)    printf 'git clone %s' "${spec#git:}" ;;
    script:trivy)      printf 'curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin' ;;
    script:grype)      printf 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin' ;;
    script:syft)       printf 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin' ;;
    script:trufflehog) printf 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin' ;;
    *)        if [ "$PLAT" = "mac" ]; then printf 'brew install %s' "$spec"; else printf 'sudo apt-get install -y %s' "$spec"; fi ;;
  esac
}

MISSING_REQUIRED=0; FIRST=1
[ "$FORMAT" = "json" ] && printf '['
[ "$FORMAT" = "text" ] && { echo "== secskills doctor =="; echo "platform: $PLAT   mode: $MODE   category: $CAT"; echo ""; }

CUR_CAT=""
while IFS=$'\t' read -r name tier category modes mac linux note; do
  [ -z "${name:-}" ] && continue
  mode_match "$modes" "$MODE" || continue
  { [ "$CAT" != "all" ] && [ "$CAT" != "$category" ]; } && continue
  [ -n "$TOOLS" ] && case "$TOOLS" in *",$name,"*) : ;; *) continue ;; esac
  if command -v "$name" >/dev/null 2>&1; then status=present; else status=absent; fi
  # headless browser: also accept macOS app bundle / common chromium names
  if [ "$name" = "chrome" ] && [ "$status" = absent ]; then
    for c in google-chrome google-chrome-stable chromium chromium-browser "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" "/Applications/Chromium.app/Contents/MacOS/Chromium"; do
      if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then status=present; note="headless browser found: $c"; break; fi
    done
  fi
  [ "$PLAT" = "mac" ] && cmd="$(render_install "$mac")" || cmd="$(render_install "$linux")"
  [ "$status" = absent ] && [ "$MODE" = sandbox ] && [ "$name" = docker ] && MISSING_REQUIRED=1
  if [ "$FORMAT" = "json" ]; then
    [ "$FIRST" -eq 0 ] && printf ','; FIRST=0
    printf '{"tool":"%s","tier":"%s","category":"%s","modes":"%s","status":"%s","install":"%s"}' \
      "$name" "$tier" "$category" "$modes" "$status" "$(printf '%s' "$cmd" | sed 's/\\/\\\\/g; s/"/\\"/g')"
  else
    [ "$category" != "$CUR_CAT" ] && { echo ""; echo "[$category]"; CUR_CAT="$category"; }
    if [ "$status" = present ]; then
      [ "$QUIET" -eq 1 ] || printf '  \xE2\x9C\x93 %-18s %-9s %s\n' "$name" "$tier" "$note"
    else
      printf '  \xE2\x9C\x97 %-18s %-9s MISSING \xE2\x80\x94 %s\n' "$name" "$tier" "$cmd"
    fi
  fi
done <<< "$REGISTRY"

[ "$FORMAT" = "json" ] && { printf ']\n'; exit $MISSING_REQUIRED; }

echo ""
if [ "$MISSING_REQUIRED" -eq 1 ]; then
  echo "RESULT: sandbox mode needs docker — install it first."
else
  echo "RESULT: ready. Each ✗ only narrows coverage. Tier \"skills\" is used by the agent skills and lib/ helpers."
fi
[ "$PLAT" = "linux" ] && echo "PATH note: go -> \$(go env GOPATH)/bin ; cargo -> ~/.cargo/bin ; pipx -> ~/.local/bin must be on PATH."
[ "$PLAT" = "mac" ] && echo "httpx note: verify projectdiscovery build — httpx --version | grep -i projectdiscovery"
exit $MISSING_REQUIRED
