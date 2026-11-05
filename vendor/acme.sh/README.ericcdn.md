Pinned upstream: https://github.com/acmesh-official/acme.sh/tree/3.1.6

Only the upstream shell client and license are bundled. SHA256SUMS records the
reviewed source bytes and is checked during installation. EricCDN supplies its own
DNS hook under lib/dns_ericcdn.sh. The client is invoked with Bash, an explicit
config home, explicit Let's Encrypt server, and no installer/automatic upgrade.
Upstream license is in LICENSE.md; the source is unmodified.
