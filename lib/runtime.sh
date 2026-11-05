#!/usr/bin/env bash
# shellcheck disable=SC2154 # The installed entrypoint supplies its private work directory.
# Paths are initialized by the installed entrypoint; tests can use an isolated root.
atomic_install() {
    local src=$1 dst=$2 mode=${3:-0600}
    install -m "$mode" "$src" "$dst.next"
    mv -f -- "$dst.next" "$dst"
}
point_release() {
    valid_id "$1" && [[ -d $CONF/releases/$1 ]] || return 1
    rm -f "$CONF/active.next"
    ln -s "releases/$1" "$CONF/active.next"
    mv -Tf "$CONF/active.next" "$CONF/active"
    sync -f "$CONF"
}
active_id() { basename "$(readlink "$CONF/active")"; }
probe_release() {
    local expected=$1 result attempt consecutive=0
    for attempt in {1..30}; do
        result=$(curl --silent --fail --max-time 2 --noproxy '*' "http://127.0.0.1:$ADMIN_PORT/_ericcdn_revision" 2>/dev/null) || result=''
        if [[ $result == "$expected" ]]; then consecutive=$((consecutive+1)); else consecutive=0; fi
        ((consecutive<3)) || return 0
        sleep 1
    done
    return 1
}
reload_release() {
    nginx -t -c "$NGINX_CONF" && systemctl reload ericcdn-nginx.service && probe_release "$1"
}
recover_release() {
    local old
    [[ -f $CONF/pending.json ]] || return 0
    old=$(jq -er '.previous' "$CONF/pending.json") || return 1
    valid_id "$old" || return 1
    point_release "$old"
    # At boot recovery happens before nginx starts. Live recovery verifies activation.
    if [[ ${1:-live} == live ]]; then reload_release "$old" || return 1; fi
    rm -f "$CONF/pending.json"
    sync -f "$CONF"
}
prepare_origins() {
    local desired=$1 output=$2 host address count
    printf '{}\n' > "$output"
    while IFS= read -r host; do
        local -a addresses=()
        while IFS= read -r address; do
            [[ -n $address ]] || continue
            public_ipv4 "$address" || { printf 'Origin %s resolved to a non-public IPv4 address.\n' "$host" >&2; return 1; }
            addresses+=("$address")
        done < <(timeout 5 getent ahostsv4 "$host" | awk '{print $1}' | sort -u)
        count=${#addresses[@]}
        ((count>0 && count<=16)) || { printf 'Origin %s must resolve to 1–16 public IPv4 addresses.\n' "$host" >&2; return 1; }
        printf '%s\n' "${addresses[@]}" | jq -Rsc --arg host "$host" 'split("\n")|map(select(.!=""))|{($host):.}' > "$output.host"
        jq -s '.[0]+.[1]' "$output" "$output.host" > "$output.next"
        mv "$output.next" "$output"
    done < <(jq -r '[.domains[] | .origin, (.policy.backup_origins // [])[]] | unique[]' "$desired")
    rm -f "$output.host"
}
apply_release() {
    local desired=$1 cert_source=$2 previous release staging
    previous=$(active_id)
    release="r$(date +%s)_${RANDOM}_${RANDOM}"
    staging="$CONF/releases/$release"
    install -d -m 0700 "$staging" "$staging/certs"
    cp "$desired" "$staging/state.json"
    [[ ! -d $cert_source ]] || cp -a "$cert_source/." "$staging/certs/"
    prepare_origins "$desired" "$staging/origins.json" || return 1
    render_state "$desired" "$CA" "$staging/certs" "$staging/origins.json" > "$staging/domains.conf" || return 1
    printf 'location = /_ericcdn_revision { default_type text/plain; return 200 "%s"; }\n' "$release" > "$staging/revision.conf"
    jq -n --arg previous "$previous" --arg next "$release" '{previous:$previous,next:$next}' > "$work/pending.json"
    atomic_install "$work/pending.json" "$CONF/pending.json"
    sync -f "$CONF"
    point_release "$release"
    if reload_release "$release"; then
        # The active release contains both config and state. The journal is the commit marker.
        rm -f "$CONF/pending.json"
        sync -f "$CONF"
    else
        recover_release live || return 1
        return 1
    fi
}
html_escape() { sed -e 's/\&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"; }
collect_metrics() {
    local state="$CONF/active/state.json" nginx_up=false disk cache now domains
    now=$(date -u +%FT%TZ)
    traffic_window
    local interval traffic total_disk secure_link=false
    interval=$(jq .seconds "$work/window.json")
    total_disk=$(df -Pk "$CACHE_DIR" | awk 'NR==2 {print $2*1024}')
    if nginx -V 2>&1 | grep -q -- --with-http_secure_link_module; then secure_link=true; fi
    systemctl is-active --quiet ericcdn-nginx.service && nginx_up=true
    disk=$(df -Pk "$CACHE_DIR" | awk 'NR==2 {print $4*1024}')
    cache=$(du -sk "$CACHE_DIR" | awk '{print $1*1024}')
    domains="$work/domain-metrics.jsonl"
    : > "$domains"
    local host cert expires remaining status
    while IFS=$'\t' read -r host cert; do
        expires=''; remaining='null'; status=http
        if [[ -n $cert ]]; then
            status=invalid
            if expires=$(openssl x509 -in "$CONF/active/certs/$cert/fullchain.pem" -noout -enddate 2>/dev/null); then
                expires=${expires#notAfter=}
                remaining=$(date -d "$expires" +%s 2>/dev/null) || remaining=0
                remaining=$(( (remaining - $(date +%s)) / 86400 ))
                status=valid
                (( remaining > 14 )) || status=expiring
                openssl x509 -in "$CONF/active/certs/$cert/fullchain.pem" -noout -checkend 0 >/dev/null 2>&1 || status=expired
            fi
        fi
        traffic=$(traffic_domain "$host" "$interval")
        jq -n --arg hostname "$host" --arg certificate_status "$status" --arg expires "$expires" \
            --argjson days "$remaining" --argjson traffic "$traffic" \
            '$traffic + {hostname:$hostname,certificate_status:$certificate_status,certificate_expires:$expires,certificate_days:$days}' >> "$domains"
    done < <(jq -r '.domains[] | [.hostname,(.certificate // "")] | @tsv' "$state")
    jq -n --arg time "$now" --argjson nginx_up "$nginx_up" --argjson cache_bytes "$cache" --argjson disk_free_bytes "$disk" \
        --argjson interval_seconds "$interval" --argjson disk_total_bytes "$total_disk" --argjson secure_link "$secure_link" \
        --slurpfile window "$work/window.json" --slurpfile domains "$domains" '{agent_version:3,capabilities:{secure_link:$secure_link},interval_seconds:$interval_seconds,disk_total_bytes:$disk_total_bytes,log_backlog_bytes:$window[0].backlog_bytes,collected_at:$time,nginx_up:$nginx_up,cache_bytes:$cache_bytes,disk_free_bytes:$disk_free_bytes,sample:"incremental access-log window",domains:$domains}'
}
write_status() {
    local status=$1 message=$2 revision now
    revision=$(jq -r .revision "$CONF/active/state.json")
    now=$(date -u +%FT%TZ)
    collect_metrics > "$work/metrics.json"
    jq -n --arg status "$status" --arg message "$message" --arg revision "$revision" --arg time "$now" \
        --slurpfile metrics "$work/metrics.json" \
        '{schema_version:1,status:$status,message:$message,applied_revision:$revision,last_sync:$time,metrics:$metrics[0]}' > "$work/status.json"
    atomic_install "$work/status.json" "$STATE/status.json"
    atomic_install "$work/status.json" "$WEB/status.json" 0644
    {
        printf '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="refresh" content="60"><title>EricCDN</title><style>body{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:1rem}td,th{padding:.6rem;text-align:left;border-bottom:1px solid #ddd}table{width:100%%}</style><h1>EricCDN local administration</h1>'
        printf '<p>Status: %s — %s</p><p>Revision: %s · Checked: %s</p>' "$status" "$(printf '%s' "$message" | html_escape)" "$revision" "$now"
        jq -r '"<p>nginx running: \(.nginx_up) · Cache bytes: \(.cache_bytes) · Disk free bytes: \(.disk_free_bytes)</p>"' "$work/metrics.json"
        printf '<p>Traffic statistics cover new requests since the previous report. Refresh: 60 seconds.</p><table><tr><th>Domain</th><th>Certificate</th><th>Days left</th><th>Requests</th><th>Hits</th><th>Misses</th><th>5xx</th></tr>'
        jq -r '.domains[] | "<tr><td>\(.hostname | @html)</td><td>\(.certificate_status)</td><td>\(.certificate_days // "—")</td><td>\(.requests)</td><td>\(.cache_hits)</td><td>\(.cache_misses)</td><td>\(.errors_5xx)</td></tr>"' "$work/metrics.json"
        printf '</table><p><a href="/nginx_status">Live counters</a> · <a href="/status.json">JSON status</a></p><p>Manage domains, cache invalidation and DNS through EricServic.es Admin.</p></html>'
    } > "$work/index.html"
    atomic_install "$work/index.html" "$WEB/index.html" 0644
}
