#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/node.sh"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
cp "$ROOT/tests/fixtures/delivery-state.json" "$TMP/state.json"
validate_state "$TMP/state.json"
render_state "$TMP/state.json" /etc/ssl/cert.pem > "$TMP/config"
for literal in 'location ^~ /private/' 'location ~* \.css$' 'proxy_ssl_name backup.example.test;' 'secure_link_md5 "$secure_link_expires$uri abcdefghijklmnopqrstuvwxyz1234567890";' 'limit_req_status 429;' 'proxy_cache_background_update on;' 'location = /old { return 308 "/new"; }'; do
    grep -Fq "$literal" "$TMP/config" || fail "Missing generated behavior: $literal"
done
for mutation in \
    '.domains[0].policy.request_rate = -1' \
    '.domains[0].policy.connect_timeout = 0' \
    '.domains[0].policy.read_timeout = 601' \
    '.domains[0].policy.signing_key = "weak"' \
    '.domains[0].policy.backup_origins = ["localhost; include /tmp/pwn;"]' \
    '.domains[0].policy.ip_allow = ["127.0.0.1; return 200;"]' \
    '.domains[0].policy.ip_deny = ["999.1.1.1"]' \
    '.domains[0].policy.cache_rules[0].value = "/foo { return 200; }"' \
    '.domains[0].policy.redirects[0].target = "//attacker.test/path"' \
    '.domains[0].policy.response_headers[0].name = "Set-Cookie"' \
    '.domains[0].policy.response_headers[0].value = "evil\nX-Injected: 1"'; do
    jq "$mutation" "$TMP/state.json" > "$TMP/invalid.json"
    if validate_state "$TMP/invalid.json" 2>/dev/null; then fail "Accepted hostile policy: $mutation"; fi
done
for cidr in '::/0' '2001:db8::/32' '127.0.0.1/32' '0.0.0.0/0'; do valid_cidr "$cidr" || fail "Rejected valid CIDR: $cidr"; done
for cidr in '1::2::3' '::1/129' '127.0.0.1/33' '01.0.0.1' 'x/1'; do if valid_cidr "$cidr"; then fail "Accepted invalid CIDR: $cidr"; fi; done
printf 'PASS: delivery/failover/protection rendering and 11 hostile policies.\n'
