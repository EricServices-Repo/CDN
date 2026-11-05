<?php
require_once __DIR__.'/../bootstrap.php';
admin_verify_post();
es_admin_redirect('/admin/cdn-bash.php','error','Use the consolidated CDN manager. Legacy node changes are retired; import existing identities before publishing replacements.');
