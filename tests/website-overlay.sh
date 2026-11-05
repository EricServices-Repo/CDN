#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURE=$(mktemp -d)
trap 'rm -rf -- "$FIXTURE"' EXIT
mkdir -p "$FIXTURE/admin/actions" "$FIXTURE/includes"
printf '<?php\n// Fixture config; no production database.\n' > "$FIXTURE/config.php"
printf '<?php\n// Fixture CDN module.\n' > "$FIXTURE/includes/cdn.php"
printf '<?php\nadmin_cdn_tabs($tab);\n' > "$FIXTURE/admin/cdn.php"
for file in cdn-save.php cdn-delete.php; do
    printf '<?php\n$uid = (int) ($_POST['"'"'uid'"'"'] ?? 0);\n' > "$FIXTURE/admin/actions/$file"
done
bash "$ROOT/integration/install-website.sh" "$FIXTURE" >/dev/null
bash "$ROOT/integration/install-website.sh" "$FIXTURE" >/dev/null
[[ $(rg -c '/admin/cdn-bash.php' "$FIXTURE/admin/cdn.php") == 1 ]]
[[ $(rg -c es_cdn2_guard_entry_change "$FIXTURE/admin/actions/cdn-delete.php") == 1 ]]
find "$FIXTURE" -name '*.php' -exec php -l {} \; >/dev/null
if command -v php-cgi >/dev/null; then
    reply=$(printf '{}' | env REDIRECT_STATUS=200 SCRIPT_FILENAME="$FIXTURE/api/cdn/v1/index.php" REQUEST_METHOD=POST CONTENT_TYPE=application/json CONTENT_LENGTH=2 php-cgi -q)
    printf '%s' "$reply" | rg -q 'Bearer token required'
fi
printf 'PASS: additive website installation, idempotent navigation/lifecycle patches and PHP entrypoint.\n'
