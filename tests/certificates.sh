#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/node.sh"
source "$ROOT/lib/certificates.sh"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 40 -subj '/CN=example.test' \
    -addext 'subjectAltName=DNS:example.test,DNS:*.assets.example.test' \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" >/dev/null 2>&1
cert_matches "$TMP/cert.pem" "$TMP/key.pem" example.test
cert_matches "$TMP/cert.pem" "$TMP/key.pem" '*.assets.example.test'
if cert_matches "$TMP/cert.pem" "$TMP/key.pem" other.example.test; then fail 'Accepted wrong SAN.'; fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/other.key" >/dev/null 2>&1
if cert_matches "$TMP/cert.pem" "$TMP/other.key" example.test; then fail 'Accepted mismatched key.'; fi
if cert_matches "$TMP/missing.pem" "$TMP/key.pem" example.test; then fail 'Accepted missing certificate.'; fi
source "$ROOT/lib/runtime.sh"
STATE="$TMP/state"; work="$TMP/work"; ACME_EMAIL=admin@example.test
mkdir -p "$STATE" "$work"
issues=0; heartbeats=0
renewal_heartbeat() { heartbeats=$((heartbeats+1)); }
bash() {
    local previous='' arg
    for arg in "$@"; do
        if [[ $arg == --issue ]]; then issues=$((issues+1)); fi
        if [[ $previous == --key-file ]]; then cp "$TMP/key.pem" "$arg"; fi
        if [[ $previous == --fullchain-file ]]; then cp "$TMP/cert.pem" "$arg"; fi
        previous=$arg
    done
}
managed_certificate example.test cert1
managed_certificate example.test cert1
[[ $issues == 1 && $heartbeats == 1 && -f $STATE/issued/cert1/fullchain.pem ]]
cert_matches "$STATE/issued/cert1/fullchain.pem" "$STATE/issued/cert1/privkey.pem" example.test
printf 'PASS: exact/wildcard SAN, host/key rejection, persistent issuance and retry reuse.\n'
