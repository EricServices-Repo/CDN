# EricServic.es CDN

A lightweight nginx caching proxy with Bash installation, configuration, certificate
renewal and health reporting. No Node.js or application server runs on CDN hosts.
The EricServic.es website integration uses its existing PHP/MySQL stack.

## Features

- Admin enrollment with expiring, address-bound grants and explicit host approval.
- Exact/wildcard CDN domain assignments and server-side Cloudflare DNS management.
- Automatic DNS-01 certificates and renewal using the bundled shell ACME client.
  DNS provider tokens stay on the website server.
- Persistent configuration releases, activation probes, rollback and crash recovery.
- Per-domain cache invalidation through cache versions; no nginx commercial module.
- Remote delivery rules, redirects, headers, CORS, download behavior and HTTPS origin failover.
- Per-IP request/connection limits, IP allow/block lists and expiring signed downloads.
- Draft previews, canary publication, promotion, history and remote rollback.
- Loopback admin status, incremental traffic/origin latency, external checks and in-app alerts.

See [remote delivery management](docs/delivery-management.md) for upgrade, publication,
legacy-registry consolidation, policy details and operational limits.

## Install the CDN host

Use a dedicated systemd host: Ubuntu 22.04+, Debian 12+, Rocky/Alma/RHEL 9+.
The installer refuses an unmanaged nginx installation. Re-running it resumes a
partial installation or upgrades this installation while preserving identity.

```bash
git clone https://github.com/EricServices-Repo/CDN.git
cd CDN
sudo bash install.sh
# Optional on first install: sudo ADMIN_PORT=9081 bash install.sh
```

Public ports are TCP 80/443 (IPv4). The static admin page listens only on
`127.0.0.1:8081`. nginx uses a 10 GB disk cache. Existing firewalld/UFW rules are
extended for public web access; the installer does not start a new firewall or
open the admin port. Configure your provider firewall too. SELinux stays enforcing.

Use an SSH tunnel for local administration from your workstation:

```bash
ssh -N -L 8081:127.0.0.1:8081 root@YOUR_CDN_HOST
```

Visit `http://127.0.0.1:8081`. Request statistics cover new access-log records since
the previous report, rather than lifetime totals. `nginx_status` provides live counters.

## Install the website integration

The source overlay is in [integration/ericservices](integration/ericservices).
Apply it to the EricServices checkout and configure its server:

```bash
bash integration/install-website.sh /path/to/EricServices
```

Run the base and delivery/deployment SQL migrations once, baseline existing configurations, configure the server's enrollment key and scoped DNS
provider token, then schedule the reconciler. Full instructions and acceptance
checks are in [docs/admin-integration.md](docs/admin-integration.md). The installer
adds a link under Admin → CDN to the new Bash node management page. Existing Python
guest agents are left separate; do not install them on these CDN hosts.

After generating an enrollment grant in Admin:

```bash
sudo ericcdn-sync enroll https://ericservic.es edge-nyc-01 admin@example.com
# Enter the token at the hidden prompt, then approve the host in Admin.
sudo ericcdn-sync sync
```

The timer runs about once a minute. Assign an active CDN entry, verified DNS zone,
exact/wildcard hostname, HTTPS origin hostname, cache TTL and approved hosts in
Admin. Enable managed TLS and DNS publication. Save the settings, create a draft, deploy a canary, and promote it after health checks pass. DNS records are created only after
hosts report that they loaded the configuration and have a ready certificate.
New certificates can take several minutes while DNS-01 validation completes.

Cloudflare is the implemented DNS adapter. Other providers need another website-side
adapter. IPv6/AAAA publication and custom origin ports/paths are not supported.
Wildcard DNS does not cover the apex; assign it separately when needed.

## Certificates and cache

The pinned `acme.sh` 3.1.6 source and upstream license are under `vendor/acme.sh`.
Installation checks its recorded SHA-256 hashes. It runs with Bash and OpenSSL,
without auto-update, cron installation, or an additional persistent daemon.

Certificates renew when fewer than 30 days remain. Failed attempts back off six
hours. Renewed keys, SAN coverage and expiry are checked before deployment. Keys
and all releases are root-only. nginx must answer the release probe before a new
configuration is committed. Use the Let's Encrypt staging directory for testing:
set `ACME_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory` in the
root-owned `/etc/ericcdn/node.conf`, then switch back before production enrollment.
Staging certificates are not browser-trusted.

Origins use HTTPS with certificate verification. Cookie/Authorization requests
bypass cache, and origin cache-control/Set-Cookie restrictions remain in effect.
TTL zero disables caching. Admin's **Invalidate domain cache** drafts an increment to its cache
version; publish the draft to activate the new cache namespace.
Old entries age out through nginx's normal cache manager, so invalidation does not
immediately reclaim their disk space.

## Recovery and operations

```bash
sudo ericcdn-sync status
sudo journalctl -u ericcdn-sync
sudo ls /etc/ericcdn/releases
sudo systemctl stop ericcdn-sync.timer
sudo ericcdn-sync rollback RELEASE_ID
```

Pause the timer before a manual rollback if retaining that revision; the next
normal poll otherwise reapplies Admin's desired configuration. Saved releases
include certificates and can eventually expire. Do not roll back to expired keys.
A pending transaction is recovered before nginx starts after reboot. There is no
automatic release pruning; retain the recovery target and delete older unneeded
releases under your retention policy. Daily nginx logs rotate with seven archives.

Drain a node/domain in Admin before removal. The website removes owned DNS records,
waits ten minutes (DNS TTL is 120 seconds), then retires assignments. Disabling or
revoking assigned hosts is blocked until draining finishes. Credential revocation
stops management; it does not stop the remote nginx process. Use host access to
stop/decommission the service when required.

## Validation

```bash
bash -n install.sh updater.sh lib/*.sh tests/*.sh integration/*.sh
bash tests/validation.sh
bash tests/runtime.sh
bash tests/certificates.sh
bash tests/delivery.sh
bash tests/traffic.sh
php tests/delivery.php
php tests/admin-validation.php
# Requires nginx and free loopback ports 18080/18443:
bash tests/nginx-smoke.sh
```

On macOS, put Homebrew OpenSSL 3 ahead of the system LibreSSL for certificate tests.
The GitHub workflow adds real MySQL tests and a disposable Ubuntu/systemd installation
test. `tests/linux-integration.sh` changes system configuration and must only run on
a disposable host with `ERICCDN_DISPOSABLE_HOST=yes`.

The development Mac has passed Bash/validation/recovery/certificate tests, PHP
validation/lint, ShellCheck, and real nginx cache/invalidation smoke tests. Live
Cloudflare/ACME operations, MySQL integration and Linux service/SELinux behavior
still require their configured test environments. Historical files under `config/`
and `sites/` are not installed; current configs are generated by the Bash scripts.
