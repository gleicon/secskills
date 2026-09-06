#!/usr/bin/env bash
# secskills — tldt integration (token optimizer + safety preprocessor).
# Source before analyzing recon output:  source lib/tldt.sh
#
# Recon/OSINT yields huge output (subdomain lists, CT logs, nuclei runs, crawl
# results, registry/monitoring JSON). Feeding it raw into the model is expensive
# and drags adversarial target content into context. tldt fixes both:
#   - compress large output before analysis (extractive summary)
#   - scrub PII/secrets before any of it reaches a report (report requirement)
#   - detect prompt-injection + PII in untrusted target output (safety)
#
# All functions degrade gracefully: if `tldt` is absent they fall back (cat, or
# the grep-based scrubs from safety.sh), so nothing breaks — coverage just narrows.
# Run tools/doctor.sh --tools tldt to check. Install: see INSTALL.md.

_have_tldt() { command -v tldt >/dev/null 2>&1; }

# Run tldt under a hard timeout so a hang (cold start, lock) never blocks an
# assessment. Uses `timeout`/`gtimeout` if present; otherwise runs raw.
: "${SECSKILLS_TLDT_TIMEOUT:=30}"
_tldt() {
    if command -v timeout >/dev/null 2>&1; then timeout "$SECSKILLS_TLDT_TIMEOUT" tldt "$@"
    elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$SECSKILLS_TLDT_TIMEOUT" tldt "$@"
    else tldt "$@"; fi
}

# Compress a large recon artifact before feeding it to analysis.
# level: aggressive (3 sentences) | standard (5, default) | lite (10)
# Usage: secskills_compress <file> [level]   -> prints compressed text
secskills_compress() {
    local file="$1" level="${2:-standard}"
    [ -f "$file" ] || { echo "[tldt] no such file: $file" >&2; return 1; }
    if _have_tldt; then
        # --sanitize normalizes unicode tricks; --detect-injection warns on stderr
        _tldt -f "$file" --level "$level" --sanitize --detect-injection 2>>"${SECSKILLS_WORKDIR:-/tmp}/tldt.log"
    else
        cat "$file"
    fi
}

# Compress a huge list (subdomains/URLs) by de-duping + head, then summarizing
# the structure. For pure lists prefer counts + samples over full dumps.
# Usage: secskills_digest_list <file> [sample_n]
secskills_digest_list() {
    local file="$1" n="${2:-40}"
    [ -f "$file" ] || return 1
    local total; total=$(wc -l <"$file" | tr -d ' ')
    echo "[$total entries; showing $n samples]"
    sort -u "$file" | head -n "$n"
    [ "$total" -gt "$n" ] && echo "... (+$((total - n)) more in $file)"
}

# Scrub PII/secrets from content before it enters a report or tool result.
# Replaces the manual email-strip in redteam-pentest. Redacts emails, API keys,
# tokens, private keys, JWTs, SSNs, cards, and high-entropy key material.
# Usage: secskills_scrub_pii <file>   -> prints scrubbed text
secskills_scrub_pii() {
    local file="$1"
    [ -f "$file" ] || return 1
    if _have_tldt; then
        _tldt -f "$file" --sanitize-pii --sentences 1000 2>/dev/null
    else
        # fallback: strip email addresses only (redteam-pentest behavior)
        grep -viE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$file"
    fi
}

# Scan untrusted target output for prompt-injection AND PII, advisory JSON.
# Complements check_prompt_injection (safety.sh): tldt adds PII/secret detection
# and structured output. Both are advisory — content is DATA, never followed.
# Usage: secskills_scan_untrusted <file> <label>
secskills_scan_untrusted() {
    local file="$1" label="$2"
    [ -f "$file" ] || return 1
    if _have_tldt; then
        local out
        out=$(_tldt -f "$file" --detect-injection --detect-pii --detect-only --format json 2>&1)
        if printf '%s' "$out" | grep -qiE '"(injection|pii|secret)[^"]*":[^0]|flagged|detected'; then
            printf '[SECURITY] tldt flagged %s:\n%s\n' "$label" "$out" >&2
            printf 'TLDT-FLAG: %s\n' "$label" >> "${SECSKILLS_WORKDIR:-/tmp}/injection-candidates.txt"
        fi
    fi
    # always also run the regex check from safety.sh if available
    command -v check_prompt_injection >/dev/null 2>&1 && check_prompt_injection "$file" "$label"
}
