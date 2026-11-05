#!/usr/bin/env bash
# Run only on a disposable Linux systemd host. Installs packages and changes /etc.
set -Eeuo pipefail
[[ ${ERICCDN_DISPOSABLE_HOST:-} == yes && $EUID -eq 0 ]] || { printf 'Set ERICCDN_DISPOSABLE_HOST=yes on a disposable test VM.\n' >&2; exit 1; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
bash "$ROOT/install.sh"
bash "$ROOT/install.sh" # Upgrade/resume must be safe and preserve service state.
systemctl is-active --quiet ericcdn-nginx
[[ $(curl -fsS http://127.0.0.1:8081/_ericcdn_revision) == "$(basename "$(readlink /etc/ericcdn/active)")" ]]
if ss -ltn | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\*|\[::\]):8081$'; then printf 'Admin exposed publicly.\n' >&2; exit 1; fi
if command -v selinuxenabled >/dev/null && selinuxenabled; then [[ $(getenforce) == Enforcing ]]; fi
bash "$ROOT/tests/validation.sh"
bash "$ROOT/tests/runtime.sh"
bash "$ROOT/tests/certificates.sh"
bash "$ROOT/tests/delivery.sh"
bash "$ROOT/tests/traffic.sh"
/usr/local/sbin/ericcdn-sync status | jq -e '.metrics.nginx_up == true'
# Exercise real nginx activation with an empty assignment set and a distinct revision.
source /usr/local/lib/ericcdn/node.sh
source /usr/local/lib/ericcdn/runtime.sh
source /etc/ericcdn/node.conf
CONF=/etc/ericcdn; STATE=/var/lib/ericcdn; WEB=/var/www/ericcdn-admin
CACHE_DIR=/var/cache/ericcdn; ACCESS_LOG=/var/log/nginx/ericcdn-access.log
NGINX_CONF=/etc/nginx/ericcdn.conf
work=$(mktemp -d /var/lib/ericcdn/test.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
printf '{"schema_version":1,"revision":"live_test","domains":[]}\n' > "$work/desired.json"
mkdir "$work/certs"
apply_release "$work/desired.json" "$work/certs"
[[ $(jq -r .revision /etc/ericcdn/active/state.json) == live_test ]]
# A malformed staged config cannot replace the last known-good live release.
printf '{"schema_version":1,"revision":"bad","domains":[{"hostname":"cdn.example.com","origin":"origin.example.com","cache_ttl":30,"certificate":"missing"}]}\n' > "$work/bad.json"
if apply_release "$work/bad.json" "$work/certs"; then printf 'Accepted missing TLS certificate.\n' >&2; exit 1; fi
[[ $(jq -r .revision /etc/ericcdn/active/state.json) == live_test ]]
systemctl restart ericcdn-nginx
probe_release "$(active_id)"
printf 'PASS: Linux install/resume, loopback admin, live activation, rejection/rollback and restart.\n'
