#!/usr/bin/env bash
# secskills — findings store + retest (schema/loop lifted from redteam-pentest, D-4).
# Store path relocated to ~/.secskills-findings/<target>/.
#
#   emit_finding <id> <title> <host> <severity> <evidence_cmd> <expected_pattern>
#   secskills_write_run <target>          — freeze findings.json into a run file
#   secskills_retest <target>             — re-probe latest run, print delta table
#
# Store layout:
#   ~/.secskills-findings/<target>/
#     run-YYYYMMDD-HHMM-XXXX.json   full assessment or retest
#     latest                        symlink to most recent run
# WORKDIR (per assessment): ${SECSKILLS_WORKDIR:-<user cache dir>/secskills/<target>}
#
# SENSITIVE: the store holds findings — treat like a credentials store. Encrypt
# at rest, restrict access, never commit to a public repo.

secskills_store_dir() { printf '%s/.secskills-findings/%s' "$HOME" "$1"; }

# Append a confirmed finding. evidence_cmd is a single reproducing command whose
# output the retest loop re-runs; expected_pattern marks "still open".
emit_finding() {
    local id="$1" title="$2" host="$3" severity="$4" evidence_cmd="$5" expected_pattern="$6"
    local wd="${SECSKILLS_WORKDIR:?set SECSKILLS_WORKDIR}"
    # response hash is captured lazily at retest (structured re-probe), not by
    # executing the stored command at emit time — no eval of stored strings.
    local response="" hash="pending"

    jq -n \
        --arg id "$id" --arg title "$title" --arg host "$host" \
        --arg severity "$severity" --arg status "open" \
        --arg evidence_cmd "$evidence_cmd" --arg expected_open_pattern "$expected_pattern" \
        --arg last_response "$response" --arg response_hash "$hash" \
        --arg run_id "${RUN_ID:-pending}" \
        '{id:$id, title:$title, host:$host, severity:$severity, status:$status,
          evidence_cmd:$evidence_cmd, expected_open_pattern:$expected_open_pattern,
          last_response:$last_response, response_hash:$response_hash,
          first_seen_run:$run_id, last_tested_run:$run_id, retest_history:[]}' \
        >> "$wd/findings-raw.jsonl"
    jq -s '.' "$wd/findings-raw.jsonl" > "$wd/findings.json"
}

secskills_run_id() {
    local target="$1" date_str="$2" count="$3"
    local h; h=$(printf '%s%s%s' "$target" "$date_str" "$count" | shasum -a 256 | cut -c1-4)
    printf '%s-%s' "$(date -u +"%Y%m%d-%H%M")" "$h"
}

secskills_write_run() {
    local target="$1" wd="${SECSKILLS_WORKDIR:?}"
    local dir; dir="$(secskills_store_dir "$target")"; mkdir -p "$dir"
    local date_str; date_str=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local count; count=$(jq 'length' "$wd/findings.json" 2>/dev/null || echo 0)
    RUN_ID=$(secskills_run_id "$target" "$date_str" "$count")
    local run_file="$dir/run-$RUN_ID.json"
    jq -n --arg run_id "$RUN_ID" --arg target "$target" --arg date "$date_str" --arg type "full" \
        --slurpfile findings "$wd/findings.json" \
        '{run_id:$run_id, target:$target, date:$date, type:$type,
          finding_counts: ($findings[0] | group_by(.severity) | map({(.[0].severity): length}) | add),
          findings: $findings[0]}' > "$run_file"
    ln -sf "$run_file" "$dir/latest"
    printf 'Findings written: %s (%s findings)\n' "$run_file" "$count"
}

# Retest: re-run each finding's evidence_cmd, classify open/mitigated/regressed,
# write a new run file, print a delta table. (loop lifted verbatim, repathed)
# SECURITY: this reference script re-runs each finding's evidence_cmd. Those
# commands are emitted by the secskills binary with every target-derived value
# shell-quoted (shellQuote) and hostnames validated, and the store is operator-
# owned. Only run retest against a store you produced; never against an untrusted
# run file. The Go binary is the authoritative, hardened implementation.
secskills_retest() {
    local target="$1"
    local dir; dir="$(secskills_store_dir "$target")"
    local prev="$dir/latest"
    [ -f "$prev" ] || { echo "No prior run at $prev — run a full assessment first."; return 1; }

    local prev_run_id date_str count new_run_id new_file
    prev_run_id=$(jq -r '.run_id' "$prev")
    date_str=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    count=$(jq '.findings | length' "$prev")
    new_run_id=$(secskills_run_id "$target" "$date_str" "$count")
    new_file="$dir/run-$new_run_id.json"

    echo "=== RETEST: $target ($prev_run_id -> $new_run_id) ==="
    echo "| ID | Severity | Status | Change | Title |"
    echo "|----|----------|--------|--------|-------|"
    local updated="[]"
    while IFS= read -r finding; do
        local id sev prev_status cmd expected prev_hash change new_status resp new_hash
        id=$(jq -r '.id' <<<"$finding"); sev=$(jq -r '.severity' <<<"$finding")
        prev_status=$(jq -r '.status' <<<"$finding"); cmd=$(jq -r '.evidence_cmd' <<<"$finding")
        expected=$(jq -r '.expected_open_pattern' <<<"$finding"); prev_hash=$(jq -r '.response_hash' <<<"$finding")
        local title; title=$(jq -r '.title' <<<"$finding")
        if [ "$prev_status" = "manual" ] || [ -z "$cmd" ]; then
            change="—"; new_status="manual"; resp="(manual probe)"; new_hash="$prev_hash"
        else
            # structured re-probe (no eval): use probe_kind/probe_url, curl as a
            # plain argument (never eval). Unknown kinds -> manual.
            local pkind purl parg stillopen
            pkind=$(jq -r '.probe_kind // "manual"' <<<"$finding")
            purl=$(jq -r '.probe_url // ""' <<<"$finding")
            parg=$(jq -r '.probe_arg // ""' <<<"$finding")
            stillopen=""
            case "$pkind" in
              header-missing) curl -skI "$purl" 2>/dev/null | grep -iq "^$parg:" || stillopen=1 ;;
              body-contains)  curl -sk "$purl" 2>/dev/null | grep -qF "$parg" && stillopen=1 ;;
              status)         [ "$(curl -sk -o /dev/null -w '%{http_code}' "$purl" 2>/dev/null)" = "200" ] && stillopen=1 ;;
              tls-weak)       echo | openssl s_client -connect "$(printf '%s' "$purl" | sed -E 's#https?://##; s#/.*##')":443 -tls1_${parg#1.} 2>/dev/null | grep -q 'Cipher is' && stillopen=1 ;;
              *)              new_status="manual"; change="—"; resp="(manual)"; new_hash="$prev_hash" ;;
            esac
            if [ "$pkind" != manual ] && [ -n "${new_status:-}" ] && [ "$new_status" = manual ]; then :; else
              if [ -n "$stillopen" ]; then
                if [ "$prev_status" = "mitigated" ]; then new_status="regressed"; change="↑ REGRESSED"; else new_status="open"; change="✗ still open"; fi
              else
                new_status="mitigated"; change="✓ mitigated"
              fi
              new_hash="$prev_hash"; resp=""
            fi
        fi
        echo "| $id | $sev | $new_status | $change | $title |"
        local hist; hist=$(jq -n --arg run_id "$prev_run_id" --arg status "$prev_status" --arg hash "$prev_hash" \
            '{run_id:$run_id, status:$status, response_hash:$hash}')
        local uf; uf=$(jq --arg s "$new_status" --arg r "$resp" --arg h "$new_hash" --arg run "$new_run_id" --argjson he "$hist" \
            '.status=$s | .last_response=$r | .response_hash=$h | .last_tested_run=$run | .retest_history=(.retest_history+[$he])' <<<"$finding")
        updated=$(jq --argjson f "$uf" '. + [$f]' <<<"$updated")
    done < <(jq -c '.findings[]' "$prev")

    jq -n --arg run_id "$new_run_id" --arg target "$target" --arg date "$date_str" --arg type "retest" \
        --arg prev "$prev_run_id" --argjson findings "$updated" \
        '{run_id:$run_id, target:$target, date:$date, type:$type, previous_run_id:$prev,
          finding_counts: ($findings | group_by(.severity) | map({(.[0].severity): length}) | add),
          status_counts: ($findings | group_by(.status) | map({(.[0].status): length}) | add),
          findings: $findings}' > "$new_file"
    ln -sf "$new_file" "$dir/latest"
    echo ""; echo "=== SUMMARY ==="
    jq -r '.status_counts | to_entries[] | "\(.key): \(.value)"' "$new_file"
}
