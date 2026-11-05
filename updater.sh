#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
LIB=${ERICCDN_LIB:-/usr/local/lib/ericcdn/node.sh}
# shellcheck source=lib/node.sh
source "$LIB"
if [[ ${1:-} == render ]]; then
    [[ $# == 3 && $3 =~ ^/[a-zA-Z0-9/_.-]+$ ]] || fail 'Usage: updater.sh render STATE_JSON CA_BUNDLE'
    render_state "$2" "$3"
    exit
fi
[[ $EUID -eq 0 ]] || fail 'Run as root.'
CONF=/etc/ericcdn
STATE=/var/lib/ericcdn
WEB=/var/www/ericcdn-admin
CACHE_DIR=/var/cache/ericcdn
ACCESS_LOG=/var/log/nginx/ericcdn-access.log
NGINX_CONF=/etc/nginx/ericcdn.conf
[[ -f $CONF/node.conf ]] || fail 'Run install.sh first.'
source "$CONF/node.conf"
source /usr/local/lib/ericcdn/runtime.sh
source /usr/local/lib/ericcdn/certificates.sh
source /usr/local/lib/ericcdn/traffic.sh
request() {
    local path=$1 body=$2 output=$3 header
    header=$(mktemp "$STATE/header.XXXXXX")
    if [[ -f $CONF/identity.json ]]; then
        jq -er '.node_token | select(type == "string" and test("^[A-Za-z0-9_-]{32,256}$")) | "Authorization: Bearer " + .' "$CONF/identity.json" > "$header"
    else cp "$CONF/enrollment.header" "$header"; fi
    local result=0 response_code
    response_code=$(curl --silent --show-error --fail --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 45 --max-filesize 1048576 \
        --request POST --header "@$header" --header 'Content-Type: application/json' \
        --data-binary "@$body" --output "$output" --write-out '%{http_code}' \
        "$ADMIN_URL/api/cdn/v1/index.php?route=$path") || result=$?
    rm -f "$header"
    [[ $response_code == 200 ]] || result=1
    return "$result"
}
renewal_heartbeat() {
    write_status applied 'Preparing certificates; the previous configuration remains active.'
    request "nodes/$node_id/report" "$STATE/status.json" "$work/progress-reply.json" >/dev/null 2>&1 || true
}
# Called by the acme.sh subprocess while the parent owns the synchronization lock.
if [[ ${1:-} == dns ]]; then
    [[ $# == 4 && ( $2 == add || $2 == remove ) && $3 == _acme-challenge.* && $4 =~ ^[A-Za-z0-9_-]{20,256}$ ]] || fail 'Invalid DNS challenge.'
    valid_host "${3#_acme-challenge.}" || fail 'Invalid challenge name.'
    [[ -f $CONF/identity.json ]] || fail 'Not enrolled.'
    node_id=$(jq -er .node_id "$CONF/identity.json")
    valid_id "$node_id" || fail 'Invalid node identity.'
    dnswork=$(mktemp -d "$STATE/dns.XXXXXX")
    trap 'rm -rf -- "$dnswork"' EXIT
    jq -n --arg name "$3" --arg value "$4" '{name:$name,value:$value}' > "$dnswork/request.json"
    request "nodes/$node_id/dns/$2" "$dnswork/request.json" "$dnswork/reply.json"
    exit
fi
exec 9>"$STATE/sync.lock"
flock -n 9 || fail 'Another installation/sync is running.'
if [[ ${1:-} == recover ]]; then
    recover_release "${2:-live}"
    exit
fi
work=$(mktemp -d "$STATE/work.XXXXXX")
# Keep an on-disk journal on uncatchable power loss; recover it before serving on boot.
report_failure=false
cleanup() {
    local result=$?
    trap - EXIT
    if [[ -f $CONF/pending.json ]]; then recover_release live || printf 'Rollback failed; inspect nginx.\n' >&2; fi
    if [[ $result != 0 && $report_failure == true ]]; then
        set +e
        write_status error 'Synchronization failed; last known-good configuration retained. Inspect journalctl -u ericcdn-sync.'
        request "nodes/$node_id/report" "$STATE/status.json" "$work/report.json" >/dev/null 2>&1
    fi
    rm -rf -- "$work"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case ${1:-sync} in
    enroll)
        [[ $# == 4 ]] || fail 'Usage: ericcdn-sync enroll https://ericservic.es NAME EMAIL'
        ADMIN_URL=${2%/}
        [[ $ADMIN_URL =~ ^https://[a-z0-9.-]+$ ]] && valid_host "${ADMIN_URL#https://}" || fail 'Admin URL must be an HTTPS hostname.'
        valid_id "$3" || fail 'Invalid node name.'
        [[ $4 =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || fail 'Invalid ACME email.'
        [[ ! -f $CONF/identity.json ]] || fail 'Already enrolled.'
        read -r -s -p 'Admin enrollment token: ' token
        printf '\n'
        [[ $token =~ ^[A-Za-z0-9_-]{32,256}$ ]] || fail 'Invalid enrollment token.'
        printf 'Authorization: Bearer %s\n' "$token" > "$CONF/enrollment.header"
        unset token
        if [[ ! -f $CONF/enrollment-id ]]; then cat /proc/sys/kernel/random/uuid > "$CONF/enrollment-id"; fi
        # Persist local settings before identity commit so an interrupted enrollment can be retried.
        sed '/^ADMIN_URL=/d;/^ACME_EMAIL=/d' "$CONF/node.conf" > "$work/node.conf"
        printf 'ADMIN_URL=%q\nACME_EMAIL=%q\n' "$ADMIN_URL" "$4" >> "$work/node.conf"
        atomic_install "$work/node.conf" "$CONF/node.conf"
        jq -n --arg name "$3" --arg id "$(cat "$CONF/enrollment-id")" \
            '{schema_version:1,name:$name,enrollment_id:$id,agent:"ericcdn-bash",version:3}' > "$work/request.json"
        request nodes/register "$work/request.json" "$work/identity.json"
        jq -e '(.node_id | type == "string" and test("^[A-Za-z0-9_-]{1,64}$")) and
          (.node_token | type == "string" and test("^[A-Za-z0-9_-]{32,256}$"))' "$work/identity.json" >/dev/null || fail 'Invalid enrollment response.'
        atomic_install "$work/identity.json" "$CONF/identity.json"
        rm -f "$CONF/enrollment.header"
        systemctl enable --now ericcdn-sync.timer
        printf 'Enrolled. Approve this host in Admin → CDN → Bash nodes.\n'
        ;;
    sync|status|rollback)
        recover_release live
        if [[ ${1:-sync} == status ]]; then
            if [[ ! -f $STATE/status.json ]]; then write_status local 'Local status refresh.'; fi
            cat "$STATE/status.json"; exit
        fi
        [[ -f $CONF/identity.json && -n ${ADMIN_URL:-} ]] || fail 'Not enrolled.'
        node_id=$(jq -er .node_id "$CONF/identity.json")
        valid_id "$node_id" || fail 'Invalid node identity.'
        report_failure=true
        if [[ ${1:-sync} == rollback ]]; then
            [[ $# == 2 ]] && valid_id "$2" && [[ -f $CONF/releases/$2/state.json ]] || fail 'Usage: ericcdn-sync rollback RELEASE_ID'
            apply_release "$CONF/releases/$2/state.json" "$CONF/releases/$2/certs" || fail 'Rollback failed.'
            write_status rolled_back 'Operator restored a saved configuration. Pause polling if retaining this revision.'
        else
            printf '{}\n' > "$work/request.json"
            request "nodes/$node_id/desired" "$work/request.json" "$work/desired.json"
            validate_state "$work/desired.json" || fail 'Invalid desired state.'
            revision=$(jq -r .revision "$work/desired.json")
            previous=$(jq -r .revision "$CONF/active/state.json")
            jq -S . "$work/desired.json" > "$work/desired.sorted"
            jq -S . "$CONF/active/state.json" > "$work/applied.sorted"
            if [[ $revision == "$previous" ]] && ! cmp -s "$work/desired.sorted" "$work/applied.sorted"; then fail 'Immutable revision was changed by Admin.'; fi
            prepare_certificates "$work/desired.json" "$work/certs"
            if ! cmp -s "$work/desired.sorted" "$work/applied.sorted" || ! diff -qr "$work/certs" "$CONF/active/certs" >/dev/null; then
                apply_release "$work/desired.json" "$work/certs" || fail 'Configuration activation failed.'
            fi
            write_status applied 'Configuration and certificates synchronized.'
        fi
        request "nodes/$node_id/report" "$STATE/status.json" "$work/report.json"
        report_failure=false
        ;;
    *) fail 'Usage: ericcdn-sync {enroll URL NAME EMAIL|sync|status|recover [boot]|rollback RELEASE_ID|render JSON CA_BUNDLE}' ;;
esac
