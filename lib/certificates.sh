#!/usr/bin/env bash
# shellcheck disable=SC2154 # The installed entrypoint supplies its private work directory.
cert_matches() {
    local cert=$1 key=$2 hostname=$3 cert_pub key_pub sans
    openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null 2>&1 || return 1
    cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256) || return 1
    key_pub=$(openssl pkey -in "$key" -pubout -outform DER | openssl dgst -sha256) || return 1
    [[ $cert_pub == "$key_pub" ]] || return 1
    sans=$(openssl x509 -in "$cert" -noout -ext subjectAltName | tr ',' '\n' | sed 's/^[[:space:]]*DNS://;s/[[:space:]]*$//')
    printf '%s\n' "$sans" | grep -Fqx -- "$hostname"
}
managed_certificate() {
    local host=$1 cert=$2 issued="$STATE/issued/$2" attempt=0 exit_code=0
    local -a common
    [[ -n ${ACME_EMAIL:-} ]] || { printf 'Configure ACME_EMAIL for managed TLS.\n' >&2; return 1; }
    install -d -m 0700 "$STATE/acme/$cert" "$issued"
    # Retain a successfully issued certificate across failed applies/restarts.
    if cert_matches "$issued/fullchain.pem" "$issued/privkey.pem" "$host" && openssl x509 -in "$issued/fullchain.pem" -noout -checkend 2592000 >/dev/null 2>&1; then return 0; fi
    [[ ! -f $STATE/acme/$cert/last-attempt ]] || read -r attempt < "$STATE/acme/$cert/last-attempt"
    [[ $attempt =~ ^[0-9]+$ ]] || attempt=0
    if (( $(date +%s) - attempt < 21600 )); then
        printf 'Certificate retry delayed for %s (six-hour backoff).\n' "$host" >&2
        return 1
    fi
    date +%s > "$STATE/acme/$cert/last-attempt"
    # Each DNS-01 attempt waits two minutes. Keep existing hosts fresh during a batch.
    renewal_heartbeat
    common=(--home /usr/local/lib/ericcdn/acme --config-home "$STATE/acme/$cert" --server "${ACME_SERVER:-letsencrypt}" --accountemail "$ACME_EMAIL")
    bash /usr/local/lib/ericcdn/acme/acme.sh "${common[@]}" --issue --dns dns_ericcdn --dnssleep 120 \
        --keylength ec-256 -d "$host" --force > "$work/acme.log" 2>&1 || exit_code=$?
    if [[ $exit_code != 0 ]]; then
        atomic_install "$work/acme.log" "$STATE/acme-last-error.log"
        printf 'Certificate issuance/renewal failed for %s; see root-only ACME log.\n' "$host" >&2
        return 1
    fi
    # acme.sh persists install paths, so they must survive this invocation's temporary directory.
    bash /usr/local/lib/ericcdn/acme/acme.sh "${common[@]}" --install-cert -d "$host" --ecc \
        --key-file "$issued/privkey.pem" --fullchain-file "$issued/fullchain.pem" > "$work/acme-install.log" 2>&1 || return 1
    cert_matches "$issued/fullchain.pem" "$issued/privkey.pem" "$host"
}
prepare_certificates() {
    local desired=$1 destination=$2 host cert managed source
    install -d -m 0700 "$destination"
    while IFS=$'\t' read -r host cert managed; do
        source="$CONF/active/certs/$cert"
        if [[ $managed == true ]]; then
            if ! cert_matches "$source/fullchain.pem" "$source/privkey.pem" "$host" || ! openssl x509 -in "$source/fullchain.pem" -noout -checkend 2592000 >/dev/null 2>&1; then
                managed_certificate "$host" "$cert" || return 1
                source="$STATE/issued/$cert"
            fi
        elif [[ -f $CONF/certs/$cert/fullchain.pem ]]; then
            # Operator-provisioned replacements can be picked up without changing the revision.
            source="$CONF/certs/$cert"
        fi
        cert_matches "$source/fullchain.pem" "$source/privkey.pem" "$host" || { printf 'Certificate/key/SAN/expiry validation failed for %s.\n' "$host" >&2; return 1; }
        install -d -m 0700 "$destination/$cert"
        install -m 0600 "$source/fullchain.pem" "$destination/$cert/fullchain.pem"
        install -m 0600 "$source/privkey.pem" "$destination/$cert/privkey.pem"
    done < <(jq -r '.domains[] | select((.certificate // "") != "") | [.hostname,.certificate,(.managed_tls // false)] | @tsv' "$desired")
}
