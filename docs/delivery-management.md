# Remote nginx delivery management

The CDN host continues to run nginx and Bash. EricServic.es Admin publishes
constrained, versioned settings; it does not send shell commands or arbitrary
nginx snippets. Host agent version 3 is required for these delivery policies.

## Upgrade sequence

1. Back up the EricServices database and host configuration/releases. Apply the
   local website overlay with `integration/install-website.sh`. Every overwritten
   source file is copied to a temporary backup directory outside the webroot.
2. Run `20261102_cdn_bash_nodes.sql` if not already installed, then run the new
   `20261103_cdn_delivery_deployments.sql` migration **once**. The latter adds
   policy storage, encrypted publication snapshots, history, alerts and probes.
3. Keep `CDN_ENROLLMENT_KEY` stable and securely backed up. It now derives the
   authenticated encryption key for configuration snapshots, including signing
   secrets. PHP needs the sodium extension. Losing/changing this key makes
   existing encrypted snapshots unreadable; rotate it through an explicit
   decrypt/re-encrypt migration, not an environment-only change.
4. Run a dry-run baseline, review it, then apply:

   ```bash
   php /path/to/EricServices/scripts/cdn-bash-baseline.php
   php /path/to/EricServices/scripts/cdn-bash-baseline.php --apply
   ```

   This freezes previously configured canonical hosts before draft publication is
   enabled. Until `--apply` completes, the host API returns 503 so hosts retain
   their running configuration rather than receiving a temporary empty state.
5. If the other `cdn_edge_*` registry has installed hosts, import their identities:

   ```bash
   php /path/to/EricServices/scripts/cdn-bash-import-legacy.php
   php /path/to/EricServices/scripts/cdn-bash-import-legacy.php --apply
   ```

   Import preserves node IDs, token hashes and the last published snapshot. It
   never deletes legacy tables. Existing published domains remain served. Recreate
   legacy domain assignments under verified zones before creating a replacement
   draft. Active enrollment grants are not imported; issue new grants in the
   canonical manager. `register.php` and `node.php` become compatibility URLs for
   the canonical API; `cdn-nodes.php` redirects to the canonical Admin page and
   legacy node mutation forms are retired.
6. Re-run `sudo bash install.sh` on each owned CDN host. It preserves identity,
   migrates the original Bash credential layout where present, installs version 3,
   regenerates nginx templates as a new release, and confirms activation. Hosts
   must report version 3 before Admin permits a new policy draft. Signed downloads
   additionally require nginx's compiled-in `http_secure_link_module`; capability
   is reported by the host and checked before drafting.
7. Keep the website reconciler scheduled every minute. It now reconciles DNS,
   completes drains, checks external availability, updates alerts and prunes
   metric history. Configure PHP CLI with the same enrollment/DNS/signing secrets
   as PHP-FPM. No jobs or database changes are run merely by copying source.

## Configure and publish

Use Admin → CDN → Manage Bash CDN nodes, domains, DNS and cache.

1. Edit a domain's primary/backup origins and delivery/protection settings. Save.
   The edit remains in the authoring database and does not change serving hosts.
2. Create a named configuration draft. Its immutable per-host snapshots capture
   both the proposed settings and the previous publication.
3. Expand **Review changes by host** for before/after configuration views. Signing
   key values are redacted. Stored snapshots use authenticated encryption.
4. Deploy to one canary host. The host polls over HTTPS, validates the settings,
   prepares certificates, generates nginx config, tests it and activates a release.
5. Wait for a fresh successful activation report and external domain checks. Then
   promote to the remaining hosts. Promotion is blocked if the canary is unhealthy,
   stale, missing external checks, or another deployment made the draft stale.
6. Roll back a deployment from its history entry when needed. Previous per-host
   publications and deployment identities are restored, supporting chained
   rollbacks. Hosts activate the rollback on their next poll. A newer deployment
   must be rolled back first; a stale rollback cannot overwrite it.

An explicit drain remains an immediate lifecycle operation: owned DNS is removed,
then a ten-minute wait expires before a system publication removes the domain
from that host. The retirement appears in deployment history. Other unpublished
policy edits are not included. DNS publication still waits for a ready host/cert.

## Delivery controls

- **Cache rules:** exact paths, path prefixes, and file extensions with per-rule
  TTL (zero bypasses cache). Precedence is exact, longest prefix, then extension.
  Limits are 30 rules per domain. Origin cache-control, cookies and Authorization
  protections remain in effect.
- **Query strings:** include them in the cache key, or explicitly ignore them for
  shared assets. Ignoring query strings does not remove them from origin requests.
  Do not enable this for query-dependent personalized content.
- **Redirects:** exact paths, 301/302/307/308, relative destinations or HTTPS URLs.
  Reserved health paths and duplicate/conflicting exact routes are rejected.
- **Headers:** controlled response headers for security/CSP/robots/exposure. Values
  are quoted and escaped in nginx. Origin versions are hidden before replacement.
  Set-Cookie and raw nginx directives are not accepted.
- **CORS:** a fixed HTTPS origin or `*`, with GET/HEAD/OPTIONS preflight support.
  Credentialed wildcard CORS is not enabled.
- **Downloads:** follow origin disposition, display inline, or force attachment.
- **Resilience:** primary plus up to three ordered HTTPS backup origins, separate
  Host/SNI verification per origin, configurable connect/read timeouts, failover
  on 500/502/503/504, and optional stale cache/background refresh. Cached stale
  content may outlive its original TTL during an outage; enable this only where
  outdated content is acceptable. GET/HEAD-only delivery makes retries safe from
  repeating state-changing methods.

## Traffic protection and signed downloads

Request limits are per source IP, with optional burst and concurrent connection
limits. Rejections use HTTP 429. IP deny rules are checked before allow rules;
a nonempty allow list denies unmatched addresses. These rules assume hosts see
real client addresses directly; a front proxy requires a separately trusted
real-IP configuration before using per-client limits.

For signed downloads, configure a high-entropy 32–128 character URL-safe key in a
website-server environment variable matching `CDN_SIGNING_[A-Z0-9_]{1,80}`. Select
that reference in the domain form and use managed HTTPS. The plaintext key is
never displayed in Admin and is encrypted in stored snapshots. The CDN host
receives it through its authenticated HTTPS configuration and stores it in
root-only releases. Signing-key rotation is a draft/publish operation.

After publication, use **Create expiring download link** on the domain. Links
use nginx's standard secure_link MD5/base64url format over `expiry + URI + space +
secret`. Paths are constrained normalized ASCII paths; maximum generated lifetime
is 24 hours. Invalid/missing signatures return 403; expired valid signatures return
410. The signature is checked before serving cached content. The generator refuses
mixed signing keys across serving hosts during a rollout. Existing links cease
working after a completed signing-key rotation.

## Monitoring

A public `/_ericcdn_health` endpoint returns only the published configuration
revision. It deliberately permits external health checks without download
signatures or IP-list access to content. The local administration page remains
loopback-only. Website probes pin the approved public IPv4 while using the actual
domain's Host/SNI, validate HTTPS, reject redirects, bound response size/time and
compare the returned revision. Wildcard checks use `health.` under the wildcard.

Origins require 1–16 public IPv4 A-record addresses per hostname. The Bash host
checks those addresses and pins them into nginx upstream groups before activation;
private/reserved resolutions are rejected, and nginx does not perform another
hostname lookup between validation and connection. Public IPv6-only origins are
not supported. Refresh a publication/cache version when origin addresses change.

The website checks up to 50 host/domain pairs per reconciler pass, rotating through
older checks first. Each probe has a five-second timeout; large fleets need an
appropriately scheduled reconciler or a larger parallel monitoring service. Two
consecutive failures open an external-availability alert. Canary promotion requires
fresh passing checks for every domain assigned to the canary, so a very large
fleet must budget monitoring capacity before rollout.

Version 3 logs tab-separated server name, status, bytes, cache status, request time
and upstream timing. Bash reads new complete lines using an inode/offset cursor,
with at most 16 MiB processed per report. Server-name attribution prevents exact
hosts from also being counted under an overlapping wildcard. Reports expose
interval request/byte counts, HIT/MISS, 5xx, bandwidth in bits/second, mean observed
origin latency, certificate expiry, disk/cache size and secure-link capability.
The local `status` command reads the latest status without consuming new traffic.

Admin retains seven days of interval history and displays hourly traffic for the
last 24 hours. Counters are best-effort operational data, not billing records:
network/report loss, process failure and unread rotated logs can leave gaps.
Reports are not a durable telemetry queue. Origin latency is a mean of interval
means in the hourly display, not a percentile.

In-app alerts cover stale hosts, nginx downtime, failed syncs, low disk space,
certificate expiry, elevated 5xx, external probe failures, DNS errors and required
agent upgrades. Alerts resolve when conditions clear and can be acknowledged.
There are no automatic outbound email/chat notifications. Resolved alerts expire
after 30 days. A missing legacy metric is treated as unknown, not healthy.

## Validation status

Locally verified: Bash/ShellCheck, hostile policy rejection, TLS key/SAN checks,
configuration activation/recovery, snapshot encryption/redaction/tamper rejection,
signed-link generation, traffic aggregation, idempotent website overlay, and real
nginx caching, headers/CORS, redirects, prefix rules, TLS origin failover, signature
validation, public-origin pinning/rejection, IP blocking and rate limiting on isolated loopback ports.

The GitHub workflow includes disposable MySQL tests for migration, enrollment,
drafts, canary gating and chained rollback, plus Linux/systemd installation and
log-cursor/rotation tests. Those environments, live Cloudflare/ACME issuance and
production migrations are not available in the development Mac session. Run them
before production deployment. Staging ACME certificates intentionally fail public
HTTPS verification; promotion requires certificates trusted by the monitoring server.
