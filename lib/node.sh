#!/usr/bin/env bash
# Bash validation/rendering. Remote data is never evaluated as code.
NODE_LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fail() { printf '%s\n' "$*" >&2; exit 1; }
valid_host() {
    local name=$1 label
    [[ ${#name} -le 253 && $name == *.* && $name != *[!a-z0-9.-]* && $name != *. ]] || return 1
    local -a labels
    IFS=. read -r -a labels <<< "$name"
    for label in "${labels[@]}"; do
        [[ ${#label} -ge 1 && ${#label} -le 63 && $label != -* && $label != *- ]] || return 1
    done
}
valid_id() { [[ $1 =~ ^[a-zA-Z0-9_-]{1,64}$ ]]; }
validate_state() {
    local file=$1 domain origin cert ttl name
    jq -e '
      type == "object" and .schema_version == 1 and
      (.revision | type == "string" and test("^[A-Za-z0-9_-]{1,64}$")) and
      (.domains | type == "array" and length <= 100) and
      all(.domains[]; type == "object" and
        (.hostname | type == "string") and (.origin | type == "string") and
        ((.certificate == null) or (.certificate | type == "string")) and
        ((.cache_version // "1") | type == "string" and test("^[A-Za-z0-9_-]{1,64}$")) and
        ((.managed_tls // false) | type == "boolean") and
        (.cache_ttl | type == "number" and floor == . and . >= 0 and . <= 604800)) and
      ([.domains[].hostname] | length == (unique | length))
    ' "$file" >/dev/null || return 1
    while IFS=$'\t' read -r domain origin ttl cert; do
        name=${domain#\*.}
        valid_host "$name" || return 1
        [[ $domain == "$name" || $domain == "*.$name" ]] || return 1
        valid_host "$origin" || return 1
        [[ $origin != "$name" ]] || return 1
        [[ -z $cert ]] || valid_id "$cert" || return 1
    done < <(jq -r '.domains[] | [.hostname,.origin,.cache_ttl,(.certificate // "")] | @tsv' "$file")
    # One certificate per hostname makes renewals and rollback deterministic.
    jq -e '[.domains[] | select(.certificate != null and .certificate != "") | .certificate] |
        length == (unique | length)' "$file" >/dev/null || return 1
    jq -e 'all(.domains[]; (.managed_tls != true) or ((.certificate // "") != ""))' "$file" >/dev/null || return 1
    jq -e -f "$NODE_LIB_DIR/policy.jq" "$file" >/dev/null || return 1
    local addr backup
    while IFS= read -r addr; do valid_cidr "$addr" || return 1; done < <(jq -r '.domains[] | (.policy.ip_allow // [])[], (.policy.ip_deny // [])[]' "$file")
    while IFS= read -r backup; do valid_host "$backup" || return 1; done < <(jq -r '.domains[] | (.policy.backup_origins // [])[]' "$file")
}
valid_cidr() {
    local value=$1 addr bits part count=0 compressed=false tail_value
    addr=${value%/*}; bits=${value#*/}
    [[ $value != */ ]] || return 1
    if [[ $addr == "$value" ]]; then bits=''; fi
    if [[ $addr == *:* ]]; then
        [[ $addr != *[!a-fA-F0-9:]* && $addr != :::* && $addr != *:::* ]] || return 1
        [[ -z $bits || ( $bits =~ ^[0-9]{1,3}$ && $((10#$bits)) -le 128 ) ]] || return 1
        if [[ $addr == *::* ]]; then
            compressed=true; tail_value=${addr#*::}; [[ $tail_value != *::* ]] || return 1
        else [[ $addr != :* && $addr != *: ]] || return 1; fi
        local -a parts
        IFS=: read -r -a parts <<< "$addr"
        for part in "${parts[@]}"; do
            [[ -n $part ]] || continue
            [[ ${#part} -le 4 ]] || return 1
            count=$((count+1))
        done
        if [[ $compressed == true ]]; then ((count<8)); else ((count==8)); fi
    else
        [[ -z $bits || ( $bits =~ ^[0-9]{1,2}$ && $((10#$bits)) -le 32 ) ]] || return 1
        [[ $addr =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
        local -a octets
        IFS=. read -r -a octets <<< "$addr"
        for part in "${octets[@]}"; do [[ ${#part} -le 3 && ( $part == 0 || $part != 0* ) ]] && ((10#$part<=255)) || return 1; done
    fi
}
nginx_quote() {
    local value=$1
    value=${value//\\/\\\\}; value=${value//\"/\\\"}; value=${value//\$/\\\$}
    printf '"%s"' "$value"
}
render_access() {
    local addr
    while IFS= read -r addr; do printf '    deny %s;\n' "$addr"; done < <(jq -r '(.ip_deny // [])[]' <<< "$POLICY_JSON")
    while IFS= read -r addr; do printf '    allow %s;\n' "$addr"; done < <(jq -r '(.ip_allow // [])[]' <<< "$POLICY_JSON")
    if [[ $(jq '(.ip_allow // [])|length' <<< "$POLICY_JSON") != 0 ]]; then printf '    deny all;\n'; fi
}
render_proxy() {
    local ttl=$1 backend=$2 rule=$3 index=$4 skip=0 query key stale connect read_timeout cors signing target
    target=$backend
    [[ -z ${ORIGIN_MAP:-} ]] || target="${DOMAIN_ID}_origin$index"
    [[ $ttl != 0 ]] || skip=1
    query=$(jq -r '.query_string // "include"' <<< "$POLICY_JSON")
    key='$request_uri'; [[ $query != ignore ]] || key='$uri'
    connect=$(jq '.connect_timeout // 5' <<< "$POLICY_JSON")
    read_timeout=$(jq '.read_timeout // 60' <<< "$POLICY_JSON")
    cors=$(jq -r '.cors_origin // ""' <<< "$POLICY_JSON")
    signing=$(jq -r '.signing_key // ""' <<< "$POLICY_JSON")
    if [[ -n $cors ]]; then printf '        if ($request_method = OPTIONS) { return 204; }\n'; fi
    if [[ -n $signing ]]; then
        printf '        if ($secure_link = "") { return 403; }\n        if ($secure_link = "0") { return 410; }\n'
    fi
    if [[ -n $cors ]]; then printf '        limit_except GET HEAD OPTIONS { deny all; }\n';
    else printf '        limit_except GET HEAD { deny all; }\n'; fi
    if (( index+1 < ${#ORIGINS[@]} )); then
        printf '        proxy_intercept_errors on;\n        error_page 500 502 503 504 = @%s_%s_b%s;\n' "$DOMAIN_ID" "$rule" "$((index+1))"
    fi
    printf '        proxy_hide_header X-EricCDN-Cache;\n'
    if [[ $(jq -r '.download // ""' <<< "$POLICY_JSON") != "" ]]; then printf '        proxy_hide_header Content-Disposition;\n'; fi
    if [[ -n $cors ]]; then printf '        proxy_hide_header Access-Control-Allow-Origin;\n        proxy_hide_header Access-Control-Allow-Methods;\n        proxy_hide_header Access-Control-Allow-Headers;\n'; fi
    local custom_header
    while IFS= read -r custom_header; do printf '        proxy_hide_header %s;\n' "$custom_header"; done < <(jq -r '(.response_headers // [])[].name' <<< "$POLICY_JSON")
    cat <<CONF
        proxy_pass https://$target;
        proxy_set_header Host $backend;
        proxy_set_header Connection "";
        proxy_http_version 1.1;
        proxy_ssl_server_name on;
        proxy_ssl_name $backend;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate $CA_PATH;
        proxy_ssl_verify_depth 5;
        proxy_connect_timeout ${connect}s;
        proxy_read_timeout ${read_timeout}s;
        proxy_cache ericcdn;
        proxy_cache_key "\$scheme|\$host|$backend|$CACHE_VERSION|$rule|$ttl|$key";
        proxy_cache_valid 200 ${ttl}s;
        proxy_cache_bypass $skip \$http_authorization \$http_cookie;
        proxy_no_cache $skip \$http_authorization \$http_cookie \$upstream_http_set_cookie;
        proxy_cache_lock on;
CONF
    stale=$(jq '.serve_stale // false' <<< "$POLICY_JSON")
    if [[ $stale == true ]]; then
        printf '        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;\n        proxy_cache_background_update on;\n'
    fi
}
render_rule() {
    local selector=$1 ttl=$2 rule=$3 index
    printf '    location %s {\n' "$selector"
    render_proxy "$ttl" "${ORIGINS[0]}" "$rule" 0
    printf '    }\n'
    for ((index=1;index<${#ORIGINS[@]};index++)); do
        printf '    location @%s_%s_b%s {\n' "$DOMAIN_ID" "$rule" "$index"
        render_proxy "$ttl" "${ORIGINS[$index]}" "$rule" "$index"
        printf '    }\n'
    done
}
render_state() {
    local file=$1 CA_PATH=$2 cert_root=${3:-/etc/ericcdn/certs} ORIGIN_MAP=${4:-}
    local DOMAIN_JSON POLICY_JSON DOMAIN_ID CACHE_VERSION domain origin ttl cert rate burst connections signing cors download header name value rule match selector rule_number
    local -a ORIGINS
    validate_state "$file" || return 1
    printf '# Generated by EricCDN.\n'
    while IFS= read -r DOMAIN_JSON; do
        domain=$(jq -r .hostname <<< "$DOMAIN_JSON"); origin=$(jq -r .origin <<< "$DOMAIN_JSON")
        ttl=$(jq .cache_ttl <<< "$DOMAIN_JSON"); cert=$(jq -r '.certificate // ""' <<< "$DOMAIN_JSON")
        CACHE_VERSION=$(jq -r '.cache_version // "1"' <<< "$DOMAIN_JSON")
        POLICY_JSON=$(jq -c '.policy // {}' <<< "$DOMAIN_JSON")
        DOMAIN_ID="ecdn$(printf '%s' "$domain" | openssl dgst -sha256 | awk '{print substr($NF,1,16)}')"
        ORIGINS=("$origin")
        while IFS= read -r value; do ORIGINS+=("$value"); done < <(jq -r '(.backup_origins // [])[]' <<< "$POLICY_JSON")
        if [[ -n $ORIGIN_MAP ]]; then
            local backend_index address
            for ((backend_index=0;backend_index<${#ORIGINS[@]};backend_index++)); do
                printf 'upstream %s_origin%s {\n' "$DOMAIN_ID" "$backend_index"
                while IFS= read -r address; do
                    public_ipv4 "$address" || return 1
                    printf '    server %s:443 max_fails=1 fail_timeout=10s;\n' "$address"
                done < <(jq -er --arg host "${ORIGINS[$backend_index]}" '.[$host][]' "$ORIGIN_MAP")
                printf '}\n'
            done
        fi
        rate=$(jq '.request_rate // 0' <<< "$POLICY_JSON"); burst=$(jq '.burst // 0' <<< "$POLICY_JSON")
        connections=$(jq '.connections // 0' <<< "$POLICY_JSON")
        if ((rate>0)); then printf 'limit_req_zone $binary_remote_addr zone=%s_req:1m rate=%sr/s;\n' "$DOMAIN_ID" "$rate"; fi
        if ((connections>0)); then printf 'limit_conn_zone $binary_remote_addr zone=%s_conn:1m;\n' "$DOMAIN_ID"; fi
        printf 'server {\n    listen 80;\n    server_name %s;\n' "$domain"
        if [[ -n $cert ]]; then
            printf '    return 308 https://$host$request_uri;\n}\nserver {\n    listen 443 ssl;\n    server_name %s;\n' "$domain"
            printf '    ssl_certificate %s/%s/fullchain.pem;\n    ssl_certificate_key %s/%s/privkey.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n' "$cert_root" "$cert" "$cert_root" "$cert"
        fi
        printf '    recursive_error_pages on;\n    add_header X-EricCDN-Cache $upstream_cache_status always;\n'
        render_access
        if ((rate>0)); then
            if ((burst>0)); then printf '    limit_req zone=%s_req burst=%s nodelay;\n' "$DOMAIN_ID" "$burst";
            else printf '    limit_req zone=%s_req;\n' "$DOMAIN_ID"; fi
            printf '    limit_req_status 429;\n'
        fi
        if ((connections>0)); then printf '    limit_conn %s_conn %s;\n    limit_conn_status 429;\n' "$DOMAIN_ID" "$connections"; fi
        signing=$(jq -r '.signing_key // ""' <<< "$POLICY_JSON")
        if [[ -n $signing ]]; then printf '    secure_link $arg_md5,$arg_expires;\n    secure_link_md5 "$secure_link_expires$uri %s";\n' "$signing"; fi
        cors=$(jq -r '.cors_origin // ""' <<< "$POLICY_JSON")
        if [[ -n $cors ]]; then
            printf '    add_header Access-Control-Allow-Origin %s always;\n    add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS" always;\n    add_header Access-Control-Allow-Headers "Range, Content-Type" always;\n' "$(nginx_quote "$cors")"
        fi
        download=$(jq -r '.download // ""' <<< "$POLICY_JSON")
        if [[ -n $download ]]; then printf '    add_header Content-Disposition "%s";\n' "$download"; fi
        while IFS= read -r header; do
            name=$(jq -r .name <<< "$header"); value=$(jq -r .value <<< "$header")
            printf '    add_header %s %s always;\n' "$name" "$(nginx_quote "$value")"
        done < <(jq -c '(.response_headers // [])[]' <<< "$POLICY_JSON")
        printf '    location = /_ericcdn_health { allow all; access_log off; default_type text/plain; return 200 "%s"; }\n' "$(jq -r .revision "$file")"
        while IFS= read -r rule; do
            printf '    location = %s { return %s %s; }\n' "$(jq -r .path <<< "$rule")" "$(jq .code <<< "$rule")" "$(nginx_quote "$(jq -r .target <<< "$rule")")"
        done < <(jq -c '(.redirects // [])[]' <<< "$POLICY_JSON")
        render_rule / "$ttl" default
        rule_number=0
        while IFS= read -r rule; do
            match=$(jq -r .match <<< "$rule"); value=$(jq -r .value <<< "$rule")
            case $match in prefix) selector="^~ $value";; exact) selector="= $value";; extension) selector="~* \\.$value\$";; esac
            render_rule "$selector" "$(jq .ttl <<< "$rule")" "rule$rule_number"
            rule_number=$((rule_number+1))
        done < <(jq -c '(.cache_rules // [])[]' <<< "$POLICY_JSON")
        printf '}\n'
    done < <(jq -c '.domains[]' "$file")
}
public_ipv4() {
    local ip=$1 a b c d
    [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && valid_cidr "$ip" || return 1
    IFS=. read -r a b c d <<< "$ip"
    ((a!=0 && a!=10 && a!=127 && a<224)) || return 1
    (( !(a==169 && b==254) && !(a==172 && b>=16 && b<=31) && !(a==192 && b==168) && !(a==100 && b>=64 && b<=127) )) || return 1
    (( !(a==192 && b==0 && (c==0 || c==2)) && !(a==198 && (b==18 || b==19)) && !(a==198 && b==51 && c==100) && !(a==203 && b==0 && c==113) ))
}
