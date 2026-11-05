#!/usr/bin/env bash
# Exercises transaction code using fake service commands; no system paths or root writes.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/node.sh"
source "$ROOT/lib/runtime.sh"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
CONF="$TMP/etc"; work="$TMP/work"; CA=/etc/ssl/cert.pem; NGINX_CONF="$TMP/nginx.conf"; ADMIN_PORT=8081
mkdir -p "$CONF/releases/initial/certs" "$work" "$TMP/certs"
printf '{"schema_version":1,"revision":"initial","domains":[]}\n' > "$CONF/releases/initial/state.json"
printf '# initial\n' > "$CONF/releases/initial/domains.conf"
ln -s releases/initial "$CONF/active"
# BSD mv's -h is GNU mv's -T for replacing a symlink-to-directory.
if [[ $(uname -s) == Darwin ]]; then
    mv() { if [[ ${1:-} == -Tf ]]; then shift; command mv -fh "$@"; else command mv "$@"; fi; }
    sync() { :; } # Production's Linux syncfs is unavailable on macOS.
fi
getent() { printf '8.8.8.8 STREAM example.test\n'; }
timeout() { shift; "$@"; }
loaded=initial; block_activation=false; invalid_config=false
nginx() { [[ $invalid_config == false ]]; }
systemctl() {
    if [[ $1 == reload ]]; then
        if [[ $block_activation == false || $(active_id) == initial ]]; then loaded=$(active_id); fi
    fi
}
curl() { printf '%s' "$loaded"; }
sleep() { :; }
printf '{"schema_version":1,"revision":"next","domains":[{"hostname":"cdn.example.com","origin":"origin.example.com","cache_ttl":30,"cache_version":"v2"}]}\n' > "$work/desired.json"
apply_release "$work/desired.json" "$TMP/certs"
[[ $(jq -r .revision "$CONF/active/state.json") == next && ! -e $CONF/pending.json && $loaded == "$(active_id)" ]]
grep -Fq '|v2|' "$CONF/active/domains.conf"
grep -Fq 'server 8.8.8.8:443' "$CONF/active/domains.conf"
grep -Fq 'proxy_ssl_name origin.example.com;' "$CONF/active/domains.conf"
# Origin resolution is pinned only after public-address validation.
getent() { printf '169.254.169.254 STREAM metadata\n'; }
before_private=$(active_id)
if apply_release "$work/desired.json" "$TMP/certs" 2>/dev/null; then fail 'Accepted a metadata origin.'; fi
[[ $(active_id) == "$before_private" ]]
getent() { printf '8.8.8.8 STREAM example.test\n'; }
# A reload command can succeed without activating anything. It must not be committed.
point_release initial; loaded=initial; block_activation=true
if apply_release "$work/desired.json" "$TMP/certs"; then fail 'Committed an unactivated release.'; fi
[[ $(active_id) == initial && ! -e $CONF/pending.json ]]
# A crash leaves a journal and a switched pointer. Boot recovery restores the prior release offline.
crashed=$(find "$CONF/releases" -mindepth 1 -maxdepth 1 -type d ! -name initial | head -1)
next=${crashed##*/}
printf '{"previous":"initial","next":"%s"}\n' "$next" > "$CONF/pending.json"
point_release "$next"
ln -s "releases/$next" "$CONF/active.next" # Power loss can leave the temporary symlink behind.
recover_release boot
[[ $(active_id) == initial && ! -e $CONF/pending.json ]]
# Corrupt journals must fail closed instead of accepting a traversal path.
printf '{"previous":"../../outside"}\n' > "$CONF/pending.json"
if recover_release boot; then fail 'Accepted corrupt recovery journal.'; fi
printf 'PASS: release activation, asynchronous reload failure, rollback, crash recovery, corrupt journal.\n'
