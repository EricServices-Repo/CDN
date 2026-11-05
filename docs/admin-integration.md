# EricServic.es Admin integration

## Source and deployment

Version 3 delivery, deployments and consolidation are documented in
[delivery-management.md](delivery-management.md). Apply that upgrade sequence as well.

The implementation overlay under `integration/ericservices` adds Bash CDN hosts to
the existing PHP/MySQL website. It does not replace the inbound Python guest-agent
transport. `integration/install-website.sh` installs new source files and adds
navigation to `admin/cdn.php`, plus lifecycle guards in `cdn-save.php` and
`cdn-delete.php`. It backs up those existing files outside the web document root
and is safe to run again. It does not migrate the live database or deploy the site.

Requirements: PHP 8.2+ with mysqli, curl, sodium and JSON; MySQL 8 or MariaDB 10.6+; HTTPS.
The existing website's `config.php`, admin session/RBAC and CSRF helpers are reused.
Do not put the CDN repository or its root-only host state inside a public webroot.

1. Apply the source overlay:

   ```bash
   bash integration/install-website.sh /path/to/EricServices
   ```

2. Back up the website database, then run the additive migration once:

   ```bash
   mysql -u ericservices -p ericservices_db < /path/to/EricServices/sql/migrations/20261102_cdn_bash_nodes.sql
   ```

3. Set the following in the website server's protected environment (also available
   to PHP-FPM and the CLI reconciler):

   - `CDN_ENROLLMENT_KEY`: at least 32 random secret characters; generate using
     `openssl rand -hex 32`. This signs idempotent enrollment responses. Keep it
     stable during grant retries; it is not sent to CDN hosts.
   - `CDN_CF_PRIMARY`: Cloudflare API token scoped to the required zones with
     Zone Read and DNS Edit permissions. Additional secrets may use names matching
     `CDN_CF_[A-Z0-9_]{1,80}`. Only environment-variable references are stored in MySQL.

4. Schedule reconciliation every minute with the website's existing cron mechanism:

   ```cron
   * * * * * /usr/bin/php /path/to/EricServices/scripts/cdn-bash-reconcile.php
   ```

   This is a website-server schedule. The CDN host uses its own systemd timer.
   The reconciler uses a MySQL advisory lock so overlapping runs cannot race DNS.
   Ensure PHP sees the Authorization header; forwarding headers from untrusted
   clients must not override `REMOTE_ADDR`. If a trusted reverse proxy is in use,
   configure its real-client-IP behavior at the web server, not in the PHP API.

5. Open Admin → CDN → **Manage Bash CDN nodes, domains, DNS and cache**.
   Verify a Cloudflare zone, create an address-bound enrollment grant, enroll the
   host, approve it, and save domain assignments linked to an active customer CDN
   entry. A grant lasts one hour and is shown once. Public IPv4 currently also
   needs to be the address Admin sees for enrollment (direct public host networking).

No production database migrations, scheduled jobs, provider mutations or live
certificate issuance are performed by copying these source files.

## Host API

All requests use POST, JSON and HTTPS with a Bearer token. The actual URL format
uses a query route, avoiding dependence on URL rewrite or PHP PATH_INFO settings:

`https://ericservic.es/api/cdn/v1/index.php?route=nodes/register`

Use the website's canonical HTTPS origin when enrolling, including `www` if your
server requires it. Redirect responses are rejected rather than forwarding tokens.
The former `register.php`/`node.php` URLs now forward to this canonical API.
Import `cdn_edge_*` identities with the dry-run/apply migration described in
[delivery-management.md](delivery-management.md) before switching installed hosts.
`cdn-nodes.php` redirects to the canonical Admin manager. Legacy tables are kept
for recovery, and active legacy grants must be replaced with canonical grants.

Routes:

- `nodes/register`: enrollment grant authentication. Request includes
  `schema_version:1`, `agent:"ericcdn-bash"`, `version:3`, a safe node name and a
  persistent `enrollment_id`. Response contains `node_id` and `node_token`.
- `nodes/ID/desired`: node authentication, `{}` request, full assignment set response.
- `nodes/ID/report`: applied/error status, revision, check timestamp and metrics.
- `nodes/ID/dns/add` and `nodes/ID/dns/remove`: DNS-01 TXT operations restricted to
  that approved node's assigned managed-TLS domains. Request `{name,value}`.

Enrollment is transactionally single-use, with same-grant/same-request retries
returning the same identity. Source addresses are bound to the grant. Only token
hashes are stored; HMAC derivation enables recovery of a lost enrollment response.
IDs and tokens use constrained URL-safe alphabets. Grant retries cannot revive a
revoked credential. IP and node request rates are limited in MySQL. Non-2xx API
responses preserve the node's last known-good configuration.

Desired state example:

```json
{
  "schema_version": 1,
  "revision": "r_immutable_content_identifier",
  "domains": [
    {"hostname":"*.assets.example.com","origin":"origin.example.com","cache_ttl":3600,"cache_version":"v2","certificate":"d42","managed_tls":true}
  ]
}
```

Revisions are content-addressed and immutable. Hostnames are unique lowercase ASCII
DNS names, optionally with a single leading wildcard. Origins are HTTPS hostnames
only; ports and paths are unsupported. TTL is an integer 0–604800; zero bypasses
cache. Each managed certificate reference belongs to one hostname. Maximum 100
domains per host. No shell commands, arbitrary nginx directives or provider tokens
are accepted in desired state. Existing HTTP/path-based origins need explicit
migration before assignment.

## DNS, certificates and draining

Zone ownership is checked through the scoped Cloudflare API token. Managed DNS
records are DNS-only A records or ACME TXT records. No AAAA is published because
host serving currently binds IPv4. Each record has a stable integration ownership
comment and its provider ID in MySQL. Creation retries can recover a record after
a provider-success/database-failure. Deletion verifies owned identity and content;
unmanaged/conflicting records are not overwritten. Expired challenge TXT records
are cleaned after one day. Provider errors are retained in the Admin page.

Admin publishes a new node address only after a fresh report confirms its desired
revision, active nginx and the domain's ready certificate. An existing healthy
last-known-good address is retained during a pending update; an unready/stale node
is removed on reconciliation. This relies on authenticated host reports rather
than an independent external HTTP probe. DNS health routing is not instantaneous:
recursive caches retain earlier answers for their TTL.

Removing a host from an assignment marks it draining. The reconciler first removes
its owned A record, then starts a ten-minute drain window. nginx retains the domain
through that window; subsequent desired state retires it. If provider deletion
fails, retirement waits. The legacy disable/delete actions refuse changes while
Bash assignments remain. Retire every assignment for an entry before deleting it.
Cloudflare/DNS propagation, upstream resolvers and clients may exceed nominal TTLs;
choose a longer drain policy where your traffic requires it.

The bundled acme.sh shell client uses a custom hook to ask Admin for scoped DNS-01
TXT changes. Certificates renew below 30 days remaining. Failure backoff is six
hours, with root-only diagnostic logs. Certificate/key match, exact SAN coverage
(including wildcards), and at least 24 hours of validity are required before
activation. A changed certificate produces a fresh local release even when the
Admin revision is unchanged. All keys are mode 0600 inside mode 0700 directories.
ACME client upgrades are explicit, checksum-recorded repository changes; runtime
auto-update is not used. Use staging issuance and a test zone before production.

## Local and remote visibility

The loopback page and JSON status expose nginx availability, disk/cache bytes,
per-domain certificate status/remaining days, interval requests, HIT/MISS, bytes,
origin latency and 5xx counts. Traffic is read incrementally using an inode/offset cursor. These are
not lifetime billing counters. The node reports the same status to Admin. Failures
update the local page and attempt a remote error report; network failures may
prevent delivery, so Admin marks a host stale after five minutes without a report.
There is no public management listener or publicly exposed purge endpoint.

## Operational limits and acceptance

Origin publication rejects private/reserved addresses, known node addresses and
managed CDN hostname loops. Apply an outbound network policy at the host/provider
boundary to block private/metadata destinations as defense against DNS changes
between validation and an nginx reload. Origin DNS is checked and pinned to public IPv4 upstreams by Bash during
release preparation; address changes require a fresh publication/reload. Domain-wide cache
invalidation can supply that new release. Rate limits, DNS retries and stale-node
thresholds should be tuned for your deployment and NAT topology.

The installer can resume a partial installation, migrate the initial Bash layout,
and upgrade its own files. Configuration releases and the pending journal survive
process death and reboot. Activation checks the unique release served by nginx,
not merely success of the signal command. Manual rollback uses a saved release;
pause polling first if the old revision should remain. Keep root-only backup
releases under a retention policy and do not restore expired certificates.

Before production:

- Run `tests/admin-database.php` against a disposable MySQL database; exercise real
  HTTP enrollment, same-request retry, cross-node denial, approval and revocation.
- Run `tests/linux-integration.sh` on disposable Ubuntu/Debian and RHEL-family VMs;
  verify reboot recovery, firewall rules, loopback-only admin and SELinux enforcing.
- Use a Cloudflare test zone and Let's Encrypt staging to test exact/wildcard
  issuance, renewal, retries and removal of only owned TXT records.
- Verify cache HIT/MISS, cookie/auth/private bypass and version invalidation using
  `tests/nginx-smoke.sh`.
- Exercise node removal while the provider is unavailable; domains must continue
  serving until DNS deletion succeeds and the drain window expires.

Local validation includes PHP lint, Bash/ShellCheck, recovery and certificate tests,
plus real nginx cache tests. Live MySQL, Linux/systemd/SELinux, provider reconciliation
and ACME staging still need their configured integration environments.
