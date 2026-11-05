#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/node.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
valid='{"schema_version":1,"revision":"test-1","domains":[{"hostname":"*.cdn.example.com","origin":"origin.example.com","cache_ttl":3600,"certificate":"example"}]}'
printf '%s\n' "$valid" > "$work/state.json"
validate_state "$work/state.json"
render_state "$work/state.json" /etc/ssl/certs/ca-certificates.crt > "$work/rendered"
grep -Fq 'server_name *.cdn.example.com;' "$work/rendered"
grep -Fq 'proxy_ssl_verify on;' "$work/rendered"
grep -Fq 'proxy_cache_bypass 0 $http_authorization $http_cookie;' "$work/rendered"
printf '%s\n' "$valid" | jq '.domains[0].cache_ttl = 0 | .domains[0].certificate = ""' > "$work/http.json"
render_state "$work/http.json" /etc/ssl/cert.pem > "$work/http.conf"
grep -Fq 'proxy_cache_bypass 1 $http_authorization $http_cookie;' "$work/http.conf"
if grep -Fq 'listen 443' "$work/http.conf"; then
    fail 'HTTP-only assignment unexpectedly enabled TLS.'
fi
for mutation in \
    '.domains[0].hostname = "evil.com; include /tmp/x;"' \
    '.domains[0].hostname = "bad..example.com"' \
    '.domains[0].hostname = "-bad.example.com"' \
    '.domains[0].origin = "127.0.0.1:8081/"' \
    '.domains[0].origin = "origin.example.com\nreturn 200;"' \
    '.domains[0].certificate = "../../secrets"' \
    '.domains[0].cache_ttl = -1' \
    '.domains[0].cache_ttl = 1.5' \
    '.domains += .domains' \
    '.revision = "<script>"' \
    '.domains = null'; do
    printf '%s\n' "$valid" | jq "$mutation" > "$work/invalid.json"
    if validate_state "$work/invalid.json" 2>/dev/null; then
        fail "Accepted invalid input: $mutation"
    fi
done
printf '{"schema_version":1,"revision":"empty","domains":[]}\n' > "$work/empty.json"
validate_state "$work/empty.json"
ERICCDN_LIB="$ROOT/lib/node.sh" bash "$ROOT/updater.sh" render "$work/empty.json" /etc/ssl/cert.pem >/dev/null
printf 'PASS: valid/wildcard/empty states, rendering, and 11 hostile or invalid inputs.\n'
