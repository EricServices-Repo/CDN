#!/usr/bin/env bash
# Dedicated nginx CDN host. Re-running resumes an interrupted install or upgrades our installation.
set -Eeuo pipefail
umask 077
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SOURCE/lib/node.sh"
[[ $EUID -eq 0 && $(uname -s) == Linux && -d /run/systemd/system ]] || fail 'Run as root on Linux with systemd.'
ADMIN_PORT=${ADMIN_PORT:-8081}
[[ $ADMIN_PORT =~ ^[0-9]{4,5}$ ]] && ((10#$ADMIN_PORT >= 1024 && 10#$ADMIN_PORT <= 65535)) || fail 'Invalid admin port.'
if [[ ! -e /etc/ericcdn/install-owner && ! -e /etc/ericcdn/node.conf ]] && command -v nginx >/dev/null; then
    fail 'Existing unmanaged nginx installation; use a dedicated host.'
fi
install -d -m 0700 /etc/ericcdn /var/lib/ericcdn
exec 9>/var/lib/ericcdn/sync.lock
flock -n 9 || fail 'Another install/sync is running.'
printf 'EricCDN\n' > /etc/ericcdn/install-owner
if command -v apt-get >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx curl jq openssl ca-certificates util-linux
    CA=/etc/ssl/certs/ca-certificates.crt
    CACHE_USER=www-data
elif command -v dnf >/dev/null; then
    dnf install -y nginx curl jq openssl ca-certificates util-linux policycoreutils-python-utils
    CA=/etc/pki/tls/certs/ca-bundle.crt
    CACHE_USER=nginx
else fail 'Supported: Ubuntu 22.04+, Debian 12+, Rocky/Alma/RHEL 9+.'; fi
systemctl disable --now nginx
install -d -m 0755 /usr/local/lib/ericcdn /usr/local/lib/ericcdn/acme/dnsapi /var/www/ericcdn-admin
install -d -m 0700 /etc/ericcdn/releases /etc/ericcdn/certs /var/lib/ericcdn/acme
install -d -m 0750 -o "$CACHE_USER" -g "$CACHE_USER" /var/cache/ericcdn
for file in node.sh runtime.sh certificates.sh traffic.sh policy.jq; do
    install -m 0644 "$SOURCE/lib/$file" "/usr/local/lib/ericcdn/$file"
done
(cd "$SOURCE/vendor/acme.sh" && sha256sum -c SHA256SUMS)
install -m 0755 "$SOURCE/vendor/acme.sh/acme.sh" /usr/local/lib/ericcdn/acme/acme.sh
install -m 0644 "$SOURCE/vendor/acme.sh/LICENSE.md" /usr/local/lib/ericcdn/acme/LICENSE.md
install -m 0644 "$SOURCE/lib/dns_ericcdn.sh" /usr/local/lib/ericcdn/acme/dnsapi/dns_ericcdn.sh
install -m 0750 "$SOURCE/updater.sh" /usr/local/sbin/ericcdn-sync
# Preserve enrollment and locally chosen settings on upgrades.
if [[ ! -f /etc/ericcdn/node.conf ]]; then
    printf 'CA=%q\nADMIN_PORT=%q\nACME_SERVER=letsencrypt\n' "$CA" "$ADMIN_PORT" > /etc/ericcdn/node.conf
fi
source /etc/ericcdn/node.conf
if [[ ! -f /etc/ericcdn/identity.json && -f /etc/ericcdn/node-id && -f /etc/ericcdn/auth.header ]]; then
    legacy_id=$(cat /etc/ericcdn/node-id)
    legacy_token=$(sed -n 's/^Authorization: Bearer //p' /etc/ericcdn/auth.header)
    valid_id "$legacy_id" && [[ $legacy_token =~ ^[A-Za-z0-9_-]{32,256}$ ]] || fail 'Invalid legacy credentials.'
    jq -n --arg id "$legacy_id" --arg token "$legacy_token" '{node_id:$id,node_token:$token}' > /etc/ericcdn/identity.json.next
    mv /etc/ericcdn/identity.json.next /etc/ericcdn/identity.json
    unset legacy_token
fi
CONF=/etc/ericcdn
STATE=/var/lib/ericcdn
WEB=/var/www/ericcdn-admin
CACHE_DIR=/var/cache/ericcdn
ACCESS_LOG=/var/log/nginx/ericcdn-access.log
NGINX_CONF=/etc/nginx/ericcdn.conf
source "$SOURCE/lib/runtime.sh"
source "$SOURCE/lib/certificates.sh"
if [[ ! -L $CONF/active ]]; then
    install -d -m 0700 "$CONF/releases/initial/certs"
    if [[ -f $STATE/applied.json ]]; then cp "$STATE/applied.json" "$CONF/releases/initial/state.json";
    else printf '{"schema_version":1,"revision":"initial","domains":[]}\n' > "$CONF/releases/initial/state.json"; fi
    cp -a "$CONF/certs/." "$CONF/releases/initial/certs/"
    prepare_origins "$CONF/releases/initial/state.json" "$CONF/releases/initial/origins.json"
    render_state "$CONF/releases/initial/state.json" "$CA" "$CONF/releases/initial/certs" "$CONF/releases/initial/origins.json" > "$CONF/releases/initial/domains.conf"
    printf 'location = /_ericcdn_revision { default_type text/plain; return 200 "initial"; }\n' > "$CONF/releases/initial/revision.conf"
    point_release initial
fi
# Back up a previous main config before writing a complete atomic replacement.
[[ ! -f $NGINX_CONF ]] || cp -p "$NGINX_CONF" "$CONF/nginx-before-upgrade.conf"
cat > "$NGINX_CONF.next" <<CONF
user $CACHE_USER;
worker_processes auto;
pid /run/ericcdn-nginx.pid;
error_log /var/log/nginx/ericcdn-error.log;
events { worker_connections 2048; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format ericcdn '\$server_name\t\$status\t\$body_bytes_sent\t\$upstream_cache_status\t\$request_time\t\$upstream_response_time';
    access_log /var/log/nginx/ericcdn-access.log ericcdn;
    sendfile on;
    proxy_cache_path /var/cache/ericcdn levels=1:2 keys_zone=ericcdn:32m max_size=10g inactive=7d use_temp_path=off;
    server { listen 80 default_server; server_name _; return 444; }
    server { listen 443 ssl default_server; ssl_reject_handshake on; server_name _; }
    server {
        listen 127.0.0.1:$ADMIN_PORT;
        server_name localhost;
        access_log off;
        root /var/www/ericcdn-admin;
        location / { try_files \$uri \$uri/ =404; }
        location = /nginx_status { stub_status; }
        include /etc/ericcdn/active/revision.conf;
    }
    include /etc/ericcdn/active/domains.conf;
}
CONF
nginx -t -c "$NGINX_CONF.next"
mv "$NGINX_CONF.next" "$NGINX_CONF"
if command -v selinuxenabled >/dev/null && selinuxenabled; then
    for spec in 'httpd_cache_t /var/cache/ericcdn(/.*)?' 'httpd_sys_content_t /var/www/ericcdn-admin(/.*)?' 'httpd_config_t /etc/ericcdn(/.*)?'; do
        read -r type path <<< "$spec"
        semanage fcontext -a -t "$type" "$path" 2>/dev/null || semanage fcontext -m -t "$type" "$path"
    done
    restorecon -R /var/cache/ericcdn /var/www/ericcdn-admin /etc/ericcdn
    if ! semanage port -l | awk '$1 == "http_port_t" {for(i=3;i<=NF;i++) print $i}' | tr -d ',' | grep -qx "$ADMIN_PORT"; then
        semanage port -a -t http_port_t -p tcp "$ADMIN_PORT" 2>/dev/null || semanage port -m -t http_port_t -p tcp "$ADMIN_PORT"
    fi
    setsebool -P httpd_can_network_connect on
fi
cat > /etc/systemd/system/ericcdn-nginx.service <<'UNIT'
[Unit]
Description=EricCDN nginx
After=network-online.target
Wants=network-online.target
[Service]
Type=forking
PIDFile=/run/ericcdn-nginx.pid
ExecStartPre=/usr/local/sbin/ericcdn-sync recover boot
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/ericcdn.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/ericcdn.conf
ExecReload=/usr/sbin/nginx -s reload -c /etc/nginx/ericcdn.conf
ExecStop=/usr/sbin/nginx -s quit -c /etc/nginx/ericcdn.conf
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/ericcdn-sync.service <<'UNIT'
[Unit]
Description=EricCDN configuration, certificates and health
After=network-online.target ericcdn-nginx.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ericcdn-sync sync
TimeoutStartSec=30min
UMask=0077
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/etc/ericcdn /var/lib/ericcdn /var/www/ericcdn-admin
NoNewPrivileges=true
UNIT
cat > /etc/systemd/system/ericcdn-sync.timer <<'UNIT'
[Unit]
Description=Poll EricServic.es Admin every minute
[Timer]
OnBootSec=1min
OnUnitInactiveSec=1min
RandomizedDelaySec=10s
[Install]
WantedBy=timers.target
UNIT
cat > /etc/logrotate.d/ericcdn <<'ROTATE'
/var/log/nginx/ericcdn-*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    sharedscripts
    postrotate
        if [ -f /run/ericcdn-nginx.pid ]; then kill -USR1 "$(cat /run/ericcdn-nginx.pid)"; fi
    endscript
}
ROTATE
systemctl daemon-reload
# Release the install lock before the service's boot-recovery preflight.
flock -u 9
systemctl enable ericcdn-nginx.service
if systemctl is-active --quiet ericcdn-nginx.service; then systemctl reload ericcdn-nginx.service;
else systemctl start ericcdn-nginx.service; fi
flock -n 9 || fail 'A sync began during upgrade; re-run the installer to finish.'
work=$(mktemp -d "$STATE/install.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
apply_release "$CONF/active/state.json" "$CONF/active/certs" || fail 'Upgraded nginx templates did not activate.'
flock -u 9
probe_release "$(active_id)" || fail 'nginx did not activate the installed configuration.'
if [[ -f $CONF/identity.json ]]; then systemctl enable --now ericcdn-sync.timer; fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-service=http --add-service=https
    firewall-cmd --reload
elif command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    ufw allow 80/tcp
    ufw allow 443/tcp
fi
printf 'Installed/upgraded. Local admin: http://127.0.0.1:%s\nEnroll: sudo ericcdn-sync enroll https://ericservic.es NAME EMAIL\n' "$ADMIN_PORT"
