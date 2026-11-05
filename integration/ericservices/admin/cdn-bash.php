<?php
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/../includes/cdn-bash.php';
$pageTitle='CDN Bash nodes'; $currentAdminPage='cdn';
function cdn_h(mixed $value): string { return htmlspecialchars(is_scalar($value) ? (string)$value : '',ENT_QUOTES,'UTF-8'); }
function cdn_form(string $operation): void {
    echo '<form method="post" action="/admin/actions/cdn-bash.php" class="my-3 flex flex-wrap items-end gap-3">';
    es_csrf_field();
    echo '<input type="hidden" name="operation" value="'.cdn_h($operation).'">';
}
function cdn_input(string $name,string $label,string $value='',string $type='text'): void {
    echo '<label class="text-sm">'.cdn_h($label).'<input class="block rounded border p-2" name="'.cdn_h($name).'" value="'.cdn_h($value).'" type="'.cdn_h($type).'" required></label>';
}
function cdn_button(string $label): void { echo '<button class="rounded bg-brand-blue px-4 py-2 text-white">'.cdn_h($label).'</button>'; }
require __DIR__.'/layout-header.php';
require __DIR__.'/cdn-controls.php';
admin_flash_render();
echo '<h1 class="text-2xl font-semibold">CDN Bash nodes</h1><p class="my-3">nginx delivery with Bash management. <a class="text-brand-blue" href="/admin/cdn.php">CDN entries</a></p>';
try {
    $deploymentReady=es_cdn2_rows($con,"SHOW TABLES LIKE 'cdn_bash_deployments'");
    if (!$deploymentReady) throw new RuntimeException('Run the delivery/deployment migration.');
    $nodes=es_cdn2_rows($con,'SELECT * FROM cdn_bash_nodes ORDER BY created_at DESC');
    $zones=es_cdn2_rows($con,'SELECT * FROM cdn_bash_zones ORDER BY name');
    $domains=es_cdn2_rows($con,'SELECT * FROM cdn_bash_domains ORDER BY hostname');
    $entries=es_cdn2_rows($con,'SELECT uid,owner,path FROM cdn WHERE status="active" ORDER BY owner,path');
} catch (Throwable $e) {
    echo '<p class="my-5 text-red-700">Run both CDN migrations (20261102_cdn_bash_nodes.sql and 20261103_cdn_delivery_deployments.sql), then the baseline migration script.</p>';
    require __DIR__.'/layout-footer.php'; exit;
}
if (isset($_SESSION['cdn_bash_grant'])) {
    echo '<section class="my-5 rounded border p-4"><h2 class="font-semibold">Enrollment token — shown once, expires in one hour</h2><code>'.cdn_h($_SESSION['cdn_bash_grant']).'</code><p>On the target host run: <code>sudo ericcdn-sync enroll https://ericservic.es NAME EMAIL</code>, then paste this token at the hidden prompt.</p></section>';
    unset($_SESSION['cdn_bash_grant']);
}
if (isset($_SESSION['cdn_signed_link'])) {
    echo '<p class="my-3 rounded border p-3">Expiring download link: <a class="break-all text-brand-blue" href="'.cdn_h($_SESSION['cdn_signed_link']).'">'.cdn_h($_SESSION['cdn_signed_link']).'</a></p>';
    unset($_SESSION['cdn_signed_link']);
}
echo '<h2 class="mt-6 text-lg font-semibold">Enroll a host</h2><p class="text-sm">The public IPv4 must also be the address Admin sees for outbound enrollment. New hosts need approval.</p>';
cdn_form('grant'); cdn_input('public_ipv4','Public IPv4'); cdn_input('location','Location'); cdn_button('Create enrollment token'); echo '</form>';
echo '<h2 class="mt-6 text-lg font-semibold">Hosts and health</h2>';
foreach ($nodes as $node) {
    $report=json_decode($node['report_json'] ?? '{}',true) ?: [];
    $fresh=$node['last_seen_at'] && strtotime($node['last_seen_at'].' UTC')>time()-300;
    $desired=es_cdn2_desired($con,$node);
    $synced=$fresh && ($report['status'] ?? '')==='applied' && ($report['applied_revision'] ?? '')===$desired['revision'];
    echo '<section class="my-4 rounded border p-4"><h3 class="font-semibold">'.cdn_h($node['name']).' · '.cdn_h($node['public_ipv4']).'</h3>';
    echo '<p>'.cdn_h($node['location']).' · '.cdn_h($node['status']).' · '.($fresh ? ($synced ? 'Applied' : 'Pending/error') : 'Stale / no report').'</p><p class="text-sm">Desired: '.cdn_h($desired['revision']).' · Applied: '.cdn_h($report['applied_revision'] ?? 'none').' · Last report: '.cdn_h($node['last_seen_at'] ?? 'never').' UTC</p>';
    if ($report) echo '<details class="my-2"><summary>Disk, certificates, interval traffic and nginx capabilities</summary><pre class="overflow-auto text-xs">'.cdn_h(json_encode($report,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)).'</pre></details>';
    if ($node['status']!=='revoked') {
        cdn_form('node'); echo '<input type="hidden" name="node_id" value="'.cdn_h($node['id']).'"><select class="rounded border p-2" name="state"><option value="approved">Approve / enable</option><option value="drain">Drain assignments</option><option value="disabled">Disable after drain</option><option value="revoked">Revoke after drain</option></select>'; cdn_button('Apply host action'); echo '</form>';
    }
    echo '</section>';
}
echo '<h2 class="mt-6 text-lg font-semibold">Verified Cloudflare zones</h2><p class="text-sm">Configure a scoped provider token in a server environment variable named CDN_CF_…; enter the variable name here. Provider secrets never go to CDN hosts.</p>';
cdn_form('zone'); cdn_input('name','Zone'); cdn_input('provider_zone_id','Cloudflare zone ID'); cdn_input('token_env','Token environment variable','CDN_CF_PRIMARY'); cdn_button('Verify and save zone'); echo '</form>';
foreach ($zones as $zone) echo '<p>'.cdn_h($zone['name']).' · '.cdn_h($zone['token_env']).'</p>';
echo '<h2 class="mt-6 text-lg font-semibold">Domain assignments</h2><p class="text-sm">DNS is published only after an approved host reports the current configuration and a ready certificate. Removing a host drains DNS before retiring its configuration.</p>';
$editId=(int)($_GET['edit'] ?? 0); $edit=[];
foreach ($domains as $domain) {
    if ((int)$domain['id']===$editId) $edit=$domain;
    $assignments=es_cdn2_rows($con,'SELECT node_id,draining,drain_until FROM cdn_bash_assignments WHERE domain_id=?',[$domain['id']]);
    echo '<section class="my-4 rounded border p-4"><h3 class="font-semibold">'.cdn_h($domain['hostname']).'</h3><p>Origin: '.cdn_h($domain['origin']).' · TTL: '.cdn_h($domain['cache_ttl']).' seconds · Cache version: v'.cdn_h($domain['cache_version']).' · '.($domain['managed_tls'] ? 'Managed TLS' : 'HTTP only').'</p>';
    foreach ($assignments as $a) echo '<p class="text-sm">'.cdn_h($a['node_id']).($a['draining'] ? ' · Draining until '.cdn_h($a['drain_until'] ?? 'DNS removal succeeds').' UTC' : ' · Assigned').'</p>';
    echo '<p class="text-sm">DNS: '.($domain['dns_enabled'] ? 'Enabled' : 'Disabled').($domain['dns_error'] ? ' · '.cdn_h($domain['dns_error']) : '').'</p><a class="text-brand-blue" href="?edit='.cdn_h($domain['id']).'">Edit assignment</a>';
    foreach (['purge'=>'Draft cache invalidation','retire'=>'Drain all hosts and DNS'] as $op=>$label) { cdn_form($op); echo '<input type="hidden" name="domain_id" value="'.cdn_h($domain['id']).'">'; cdn_button($label); echo '</form>'; }
    $policy=es_cdn3_policy(json_decode($domain['policy_json'] ?? '{}',true) ?: []);
    if ($policy['signed_url_env']!=='') {
        cdn_form('sign'); echo '<input type="hidden" name="domain_id" value="'.cdn_h($domain['id']).'">';
        cdn_input('download_host','Download hostname',str_starts_with($domain['hostname'],'*.') ? '' : $domain['hostname']);
        cdn_input('download_path','Download path','/'); cdn_input('download_ttl','Link lifetime (seconds)','3600','number');
        cdn_button('Create expiring download link'); echo '</form>';
    }
    echo '</section>';
}
echo '<h3 class="mt-5 font-semibold">'.($edit ? 'Edit domain' : 'Add domain').'</h3>';
cdn_form('domain'); echo '<input type="hidden" name="domain_id" value="'.cdn_h($edit['id'] ?? 0).'">';
echo '<label class="text-sm">Active CDN entry<select class="block rounded border p-2" name="cdn_uid" required>';
foreach ($entries as $entry) echo '<option value="'.cdn_h($entry['uid']).'"'.((int)($edit['cdn_uid'] ?? 0)===(int)$entry['uid'] ? ' selected' : '').'>'.cdn_h($entry['owner'].' · '.$entry['path']).'</option>';
echo '</select></label><label class="text-sm">Verified zone<select class="block rounded border p-2" name="zone_id" required>';
foreach ($zones as $zone) echo '<option value="'.cdn_h($zone['id']).'"'.((int)($edit['zone_id'] ?? 0)===(int)$zone['id'] ? ' selected' : '').'>'.cdn_h($zone['name']).'</option>';
echo '</select></label>';
cdn_input('hostname','Exact / wildcard hostname',$edit['hostname'] ?? ''); cdn_input('origin','HTTPS origin hostname',$edit['origin'] ?? ''); cdn_input('cache_ttl','Cache TTL seconds',(string)($edit['cache_ttl'] ?? 3600),'number');
echo '<label><input type="checkbox" name="managed_tls" value="1"'.(!$edit || $edit['managed_tls'] ? ' checked' : '').'> Automatic TLS / DNS-01</label><label><input type="checkbox" name="dns_enabled" value="1"'.(!empty($edit['dns_enabled']) ? ' checked' : '').'> Publish DNS</label>';
$selected=$edit ? array_column(es_cdn2_rows($con,'SELECT node_id FROM cdn_bash_assignments WHERE domain_id=? AND draining=0',[$edit['id']]),'node_id') : [];
foreach ($nodes as $node) if ($node['status']==='approved') echo '<label><input type="checkbox" name="node_ids[]" value="'.cdn_h($node['id']).'"'.(in_array($node['id'],$selected,true) ? ' checked' : '').'> '.cdn_h($node['name']).'</label>';
cdn3_policy_fields($edit);
cdn_button('Save draft assignment'); echo '</form>';
cdn_form('reconcile'); cdn_button('Reconcile DNS now'); echo '</form><p class="my-3 text-sm">Run scripts/cdn-bash-reconcile.php every minute on the website server to reconcile DNS and finish drains.</p>';
cdn3_deployment_view($con,$nodes);
cdn3_monitor_view($con);
require __DIR__.'/layout-footer.php';
