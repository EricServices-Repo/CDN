#!/usr/bin/env bash
# Real nginx test on unprivileged loopback ports; no system configuration is changed.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/node.sh"
ERICCDN_NGINX_BINARY=${ERICCDN_NGINX_BINARY:-nginx}
TMP=$(mktemp -d)
cleanup() {
    local result=$?
    if ((result!=0)); then
        printf 'nginx smoke test failed; recent nginx diagnostics:\n' >&2
        [[ ! -f $TMP/logs/error.log ]] || tail -80 "$TMP/logs/error.log" >&2
    fi
    "$ERICCDN_NGINX_BINARY" -p "$TMP/" -c "$TMP/nginx.conf" -s quit >/dev/null 2>&1 || true
    rm -rf -- "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/cache" "$TMP/logs"
openssl req -x509 -newkey rsa:2048 -nodes -days 3 -subj '/CN=origin.example.test' \
    -addext 'subjectAltName=DNS:origin.example.test,DNS:backup.example.test' -addext 'basicConstraints=critical,CA:TRUE' \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" >/dev/null 2>&1
printf '{"schema_version":1,"revision":"test","domains":[{"hostname":"cdn.example.test","origin":"origin.example.test","cache_ttl":3600,"cache_version":"v1"}]}\n' > "$TMP/state.json"
render() {
    # The test origin uses a nonprivileged port and an isolated loopback address.
    render_state "$TMP/state.json" "$TMP/cert.pem" | sed -e 's/listen 80;/listen 127.0.0.1:18080;/' -e 's@proxy_pass https://origin.example.test;@proxy_pass https://127.0.0.1:18443;@' -e 's@proxy_pass https://backup.example.test;@proxy_pass https://127.0.0.1:18444;@' > "$TMP/domains.conf"
}
origin() {
    cat > "$TMP/origin.conf" <<CONF
server {
    listen 127.0.0.1:18443 ssl;
    ssl_certificate $TMP/cert.pem;
    ssl_certificate_key $TMP/key.pem;
    location / { add_header Cache-Control "public, max-age=3600"; return 200 "$1"; }
    location = /failover { return 503; }
    location = /private { add_header Cache-Control "private, no-store"; return 200 "private"; }
}
CONF
}
render; origin origin-v1
cat > "$TMP/backup.conf" <<CONF
server {
    listen 127.0.0.1:18444 ssl;
    ssl_certificate $TMP/cert.pem;
    ssl_certificate_key $TMP/key.pem;
    location / { return 200 "backup-response"; }
}
CONF
cat > "$TMP/nginx.conf" <<CONF
pid $TMP/nginx.pid;
error_log $TMP/logs/error.log;
events { worker_connections 128; }
http {
    access_log off;
    proxy_temp_path $TMP/proxy-temp;
    proxy_cache_path $TMP/cache keys_zone=ericcdn:1m max_size=10m use_temp_path=off;
    include $TMP/domains.conf;
    include $TMP/origin.conf;
    include $TMP/backup.conf;
}
CONF
"$ERICCDN_NGINX_BINARY" -t -p "$TMP/" -c "$TMP/nginx.conf"
"$ERICCDN_NGINX_BINARY" -p "$TMP/" -c "$TMP/nginx.conf"
get() { curl -fsS --max-time 10 --noproxy '*' -H 'Host: cdn.example.test' -D "$TMP/headers" "http://127.0.0.1:18080${1:-/}" -o "$TMP/body"; }
get; grep -Fq origin-v1 "$TMP/body"; grep -Fiq 'X-EricCDN-Cache: MISS' "$TMP/headers"
get; grep -Fiq 'X-EricCDN-Cache: HIT' "$TMP/headers"
curl -fsS --max-time 10 --noproxy '*' -H 'Host: cdn.example.test' -H 'Authorization: Bearer test' -D "$TMP/headers" http://127.0.0.1:18080/ -o /dev/null
grep -Fiq 'X-EricCDN-Cache: BYPASS' "$TMP/headers"
curl -fsS --max-time 10 --noproxy '*' -H 'Host: cdn.example.test' -H 'Cookie: session=test' -D "$TMP/headers" http://127.0.0.1:18080/ -o /dev/null
grep -Fiq 'X-EricCDN-Cache: BYPASS' "$TMP/headers"
get /private; get /private; grep -Fiq 'X-EricCDN-Cache: MISS' "$TMP/headers"
origin origin-v2
"$ERICCDN_NGINX_BINARY" -s reload -p "$TMP/" -c "$TMP/nginx.conf"
for attempt in {1..30}; do
    if curl -fsS --max-time 5 --noproxy '*' --cacert "$TMP/cert.pem" --resolve origin.example.test:18443:127.0.0.1 https://origin.example.test:18443/ | grep -Fq origin-v2; then break; fi
    sleep 0.1
done
get; grep -Fq origin-v1 "$TMP/body" # Existing cache stays valid until invalidation.
jq '.domains[0].cache_version="v2"' "$TMP/state.json" > "$TMP/next.json"
mv "$TMP/next.json" "$TMP/state.json"; render
"$ERICCDN_NGINX_BINARY" -t -p "$TMP/" -c "$TMP/nginx.conf"
"$ERICCDN_NGINX_BINARY" -s reload -p "$TMP/" -c "$TMP/nginx.conf"
for attempt in {1..30}; do
    get
    if grep -Fq origin-v2 "$TMP/body"; then break; fi
    sleep 0.1
done
grep -Fq origin-v2 "$TMP/body"
get; grep -Fiq 'X-EricCDN-Cache: HIT' "$TMP/headers"
# Apply delivery controls to the live nginx process.
jq '.revision="delivery_live" | .domains[0].cache_version="v4" | .domains[0].policy={backup_origins:["backup.example.test"],query_string:"ignore",cors_origin:"https://app.example.test",download:"attachment",cache_rules:[{match:"prefix",value:"/private/",ttl:0}],redirects:[{path:"/old",target:"/new",code:308}],response_headers:[{name:"X-Content-Type-Options",value:"nosniff"}]}' "$TMP/state.json" > "$TMP/next.json"
mv "$TMP/next.json" "$TMP/state.json"
activate() {
    render
    "$ERICCDN_NGINX_BINARY" -t -p "$TMP/" -c "$TMP/nginx.conf"
    "$ERICCDN_NGINX_BINARY" -s reload -p "$TMP/" -c "$TMP/nginx.conf"
    local expected
    expected=$(jq -r .revision "$TMP/state.json")
    for attempt in {1..30}; do
        get /_ericcdn_health
        if [[ $(cat "$TMP/body") == "$expected" ]]; then sleep 0.2; return 0; fi
        sleep 0.1
    done
    fail 'New delivery revision did not activate.'
}
activate
get '/q?a=1'; grep -Fiq 'X-EricCDN-Cache: MISS' "$TMP/headers"
get '/q?a=2'; grep -Fiq 'X-EricCDN-Cache: HIT' "$TMP/headers"
grep -Fiq 'X-Content-Type-Options: nosniff' "$TMP/headers"
grep -Fiq 'Access-Control-Allow-Origin: https://app.example.test' "$TMP/headers"
grep -Fiq 'Content-Disposition: attachment' "$TMP/headers"
get /private/file; get /private/file; grep -Fiq 'X-EricCDN-Cache: BYPASS' "$TMP/headers"
get /old; grep -Fq '308' "$TMP/headers"; grep -Fiq 'Location:' "$TMP/headers"
get /failover; grep -Fq backup-response "$TMP/body"
code=$(curl -sS --max-time 10 --noproxy '*' -X OPTIONS -H 'Host: cdn.example.test' -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/)
[[ $code == 204 ]]
# Signed URLs are checked before serving either cached or origin content.
secret=abcdefghijklmnopqrstuvwxyz1234567890
jq --arg key "$secret" '.revision="signed_live" | .domains[0].policy.signing_key=$key' "$TMP/state.json" > "$TMP/next.json"
mv "$TMP/next.json" "$TMP/state.json"; activate
status_code() { curl -sS --max-time 10 --noproxy '*' -H 'Host: cdn.example.test' -o "$TMP/body" -w '%{http_code}' "http://127.0.0.1:18080$1"; }
[[ $(status_code /signed.css) == 403 ]]
make_signed() {
    local expiry=$1 digest
    digest=$(printf '%s' "${expiry}/signed.css $secret" | openssl dgst -md5 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    printf '/signed.css?md5=%s&expires=%s' "$digest" "$expiry"
}
[[ $(status_code "$(make_signed "$(($(date +%s)+60))")") == 200 ]]
[[ $(status_code "$(make_signed "$(($(date +%s)-60))")") == 410 ]]
# The IP block list applies even to a correctly signed download.
jq '.revision="blocked_live" | .domains[0].policy.ip_deny=["127.0.0.1/32"]' "$TMP/state.json" > "$TMP/next.json"
mv "$TMP/next.json" "$TMP/state.json"; activate
[[ $(status_code "$(make_signed "$(($(date +%s)+60))")") == 403 ]]
jq '.revision="limited_live" | .domains[0].policy.ip_deny=[] | .domains[0].policy.request_rate=1' "$TMP/state.json" > "$TMP/next.json"
mv "$TMP/next.json" "$TMP/state.json"; activate
limited=0
for attempt in {1..8}; do
    code=$(status_code "$(make_signed "$(($(date +%s)+60))")")
    [[ $code != 429 ]] || limited=$((limited+1))
done
((limited>0))
printf 'PASS: real nginx cache, invalidation, headers/CORS, redirects, path rules, TLS origin failover, signed URLs, IP blocks and rate limiting.\n'
