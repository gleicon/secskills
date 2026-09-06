#!/usr/bin/env bash
# secskills — polite throttling for free OSINT/data sources.
# Source it:  source lib/throttle.sh
#
# Free endpoints (crt.sh, Wayback, Common Crawl, OSV, urlscan, OTX) block or
# tarpit aggressive clients. This enforces a conservative per-source minimum
# interval, a real User-Agent, and exponential backoff that honors Retry-After.
#
# Public API:
#   secskills_throttle <source>              — sleep so calls to <source> respect its interval
#   secskills_fetch <source> <url> [curl…]   — throttled GET with backoff; body -> stdout, code -> return
#   secskills_post  <source> <url> <data> [curl…] — throttled POST (e.g. OSV batch)
#   secskills_source_interval <source>       — print the min seconds between calls
#
# <source> is a short key: crtsh | wayback | commoncrawl | osv | urlscan | otx |
#   shodan | github | fofa | chaos | censys | virustotal | default
#
# Env overrides:
#   SECSKILLS_UA          User-Agent (default identifies as authorized assessment)
#   SECSKILLS_HTTP_RETRIES  max retries on 429/503/timeout (default 4)
#   SECSKILLS_WORKDIR     holds per-source timestamps under .throttle/

: "${SECSKILLS_UA:=secskills/0.2 (+authorized-security-assessment)}"
: "${SECSKILLS_HTTP_RETRIES:=4}"
: "${SECSKILLS_WORKDIR:=/tmp/secskills}"

# Conservative minimum seconds between calls, per free source. Tuned to stay well
# under each service's unauthenticated limits so an engagement is never blocked.
secskills_source_interval() {
    case "$1" in
        crtsh)        echo 2.0 ;;   # crt.sh is slow + blocks bursts
        wayback)      echo 2.0 ;;   # web.archive.org / cdx blocks aggressively
        commoncrawl)  echo 1.0 ;;   # index.commoncrawl.org
        otx)          echo 1.0 ;;   # AlienVault OTX
        urlscan)      echo 2.0 ;;   # ~ under 60/min unauth
        osv)          echo 0.2 ;;   # api.osv.dev generous; still polite, prefer batch
        shodan)       echo 1.0 ;;   # free plan ~1 req/s
        github)       echo 2.0 ;;   # 60/hr unauth -> go very slow without token
        fofa)         echo 1.0 ;;
        chaos)        echo 1.0 ;;
        censys)       echo 1.0 ;;
        virustotal)   echo 4.0 ;;   # free tier 4 req/min
        *)            echo 1.0 ;;   # default: 1 req/s
    esac
}

_now() { python3 -c 'import time;print("%.3f"%time.time())'; }

secskills_throttle() {
    local source="$1"
    local interval; interval=$(secskills_source_interval "$source")
    local dir="$SECSKILLS_WORKDIR/.throttle"; mkdir -p "$dir"
    local stamp="$dir/$source"
    local now last wait
    now=$(_now)
    if [ -f "$stamp" ]; then
        last=$(cat "$stamp" 2>/dev/null || echo 0)
        wait=$(python3 -c "n=$now;l=$last;i=$interval;d=i-(n-l);print('%.3f'%(d if d>0 else 0))")
        # sleep only if positive
        if [ "$(python3 -c "print(1 if $wait>0 else 0)")" = "1" ]; then sleep "$wait"; fi
    fi
    _now > "$stamp"
}

# GET with per-source throttle + backoff. Body to stdout; returns 0 on 2xx.
secskills_fetch() {
    local source="$1" url="$2"; shift 2
    local attempt=0 code retry_after body_file
    body_file="$(mktemp "${TMPDIR:-/tmp}/secskills-fetch.XXXXXX")"
    while :; do
        secskills_throttle "$source"
        code=$(curl -sS -A "$SECSKILLS_UA" --compressed --max-time 25 \
                    -o "$body_file" -w '%{http_code}' -D "$body_file.hdr" "$@" "$url" 2>/dev/null || echo 000)
        case "$code" in
            2*) cat "$body_file"; rm -f "$body_file" "$body_file.hdr"; return 0 ;;
            429|503)
                attempt=$((attempt+1))
                [ "$attempt" -gt "$SECSKILLS_HTTP_RETRIES" ] && break
                retry_after=$(grep -i '^retry-after:' "$body_file.hdr" 2>/dev/null | awk '{print $2}' | tr -d '\r')
                if printf '%s' "$retry_after" | grep -qE '^[0-9]+$'; then
                    printf '[throttle] %s %s -> %s, honoring Retry-After %ss\n' "$source" "$url" "$code" "$retry_after" >&2
                    sleep "$retry_after"
                else
                    local back; back=$(python3 -c "print(min(60, 2**$attempt))")
                    printf '[throttle] %s %s -> %s, backoff %ss (attempt %s)\n' "$source" "$url" "$code" "$back" "$attempt" >&2
                    sleep "$back"
                fi ;;
            000|5*)
                attempt=$((attempt+1))
                [ "$attempt" -gt "$SECSKILLS_HTTP_RETRIES" ] && break
                local back; back=$(python3 -c "print(min(60, 2**$attempt))")
                printf '[throttle] %s %s -> %s (timeout/err), backoff %ss\n' "$source" "$url" "$code" "$back" >&2
                sleep "$back" ;;
            *) printf '[throttle] %s %s -> %s (giving up)\n' "$source" "$url" "$code" >&2; break ;;
        esac
    done
    rm -f "$body_file" "$body_file.hdr"
    return 1
}

# POST (e.g. OSV batch query). data is the request body.
secskills_post() {
    local source="$1" url="$2" data="$3"; shift 3
    secskills_fetch "$source" "$url" -X POST -H "Content-Type: application/json" -d "$data" "$@"
}
