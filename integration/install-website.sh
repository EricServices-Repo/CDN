#!/usr/bin/env bash
# Install the additive website module and add navigation/lifecycle guards.
set -Eeuo pipefail
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TARGET=${1:?Usage: bash integration/install-website.sh /path/to/EricServices}
[[ -f $TARGET/admin/cdn.php && -f $TARGET/includes/cdn.php && -f $TARGET/config.php ]] || { printf 'Not an EricServices website checkout.\n' >&2; exit 1; }
# Existing files are backed up once per invocation, outside the web document root.
backup=$(mktemp -d "${TMPDIR:-/tmp}/ericcdn-website-backup.XXXXXX")
for file in admin/cdn.php admin/actions/cdn-save.php admin/actions/cdn-delete.php; do
    mkdir -p "$backup/$(dirname "$file")"
    cp -p "$TARGET/$file" "$backup/$file"
done
while IFS= read -r file; do
    relative=${file#"$SOURCE/ericservices/"}
    if [[ -f $TARGET/$relative ]]; then
        mkdir -p "$backup/$(dirname "$relative")"
        cp -p "$TARGET/$relative" "$backup/$relative"
    fi
    mkdir -p "$TARGET/$(dirname "$relative")"
    cp "$file" "$TARGET/$relative"
done < <(find "$SOURCE/ericservices" -type f)
# PHP script arguments avoid shell interpolation and support idempotent patches.
php "$SOURCE/patch-website.php" "$TARGET"
printf 'Website source installed. Backups: %s\nRun the SQL migration and configure server secrets/cron before enrollment.\n' "$backup"
