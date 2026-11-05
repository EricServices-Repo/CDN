<?php
$root=$argv[1] ?? '';
$path=$root.'/admin/cdn.php';
$source=file_get_contents($path);
if (!str_contains($source,'/admin/cdn-bash.php')) {
    $needle='admin_cdn_tabs($tab);';
    if (substr_count($source,$needle)!==1) throw new RuntimeException('Cannot identify CDN navigation insertion point.');
    $source=str_replace($needle,$needle."\necho '<p class=\"mb-5\"><a class=\"text-brand-blue\" href=\"/admin/cdn-bash.php\">Manage Bash CDN nodes, domains, DNS and cache</a></p>';",$source);
    file_put_contents($path,$source);
}
foreach (['cdn-save.php','cdn-delete.php'] as $file) {
    $path=$root.'/admin/actions/'.$file;
    $source=file_get_contents($path);
    if (str_contains($source,'es_cdn2_guard_entry_change')) continue;
    $needle="\$uid = (int) (\$_POST['uid'] ?? 0);";
    if (substr_count($source,$needle)!==1) throw new RuntimeException('Cannot identify CDN lifecycle guard insertion point.');
    $condition=$file==='cdn-delete.php' ? 'true' : "isset(\$_POST['status']) && \$_POST['status'] !== 'active'";
    $patch="\nrequire_once __DIR__ . '/../../includes/cdn-bash.php';\n".
        "if (\$uid > 0 && ($condition)) {\n".
        "    try { es_cdn2_guard_entry_change(\$con, \$uid); }\n".
        "    catch (RuntimeException \$e) { es_admin_redirect('/admin/cdn-bash.php', 'error', \$e->getMessage()); }\n}\n";
    file_put_contents($path,str_replace($needle,$needle.$patch,$source));
}
