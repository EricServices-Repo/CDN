<?php
/** Additive, idempotent import. Never deletes legacy data or converts active grants. */
if (PHP_SAPI!=='cli') { http_response_code(404); exit; }
require_once __DIR__.'/../config.php';
require_once __DIR__.'/../includes/cdn-bash.php';
$apply=in_array('--apply',$argv,true);
if (!es_cdn2_rows($con,"SHOW TABLES LIKE 'cdn_edge_nodes'")) { echo "No legacy CDN node registry.\n"; exit; }
foreach (es_cdn2_rows($con,'SELECT * FROM cdn_edge_nodes ORDER BY id') as $old) {
    if (es_cdn2_rows($con,'SELECT id FROM cdn_bash_nodes WHERE id=?',[$old['node_id']])) { echo 'Already imported '.$old['node_id']."\n"; continue; }
    $addresses=json_decode($old['expected_addresses_json'],true) ?: [];
    $ip=null;
    foreach ($addresses as $address) if (filter_var($address,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) && es_cdn2_public_ip($address)) { $ip=$address; break; }
    if (!$ip) throw new RuntimeException('Approve a public IPv4 for '.$old['node_id'].' before importing.');
    $snapshot=es_cdn2_rows($con,'SELECT desired_json FROM cdn_edge_snapshots WHERE node_id=? AND revision=?',[$old['node_id'],$old['desired_revision']])[0] ?? null;
    $state=$snapshot ? json_decode($snapshot['desired_json'],true,64,JSON_THROW_ON_ERROR) : es_cdn3_state([]);
    if (!is_array($state['domains'] ?? null) || count($state['domains'])>100) throw new RuntimeException('Invalid legacy snapshot.');
    echo ($apply ? 'Import ' : 'Would import ').$old['node_id'].'; preserve its credential hash and published snapshot ('.count($state['domains'])." domains).\n";
    if (!$apply) continue;
    $status=$old['status']==='revoked' ? 'revoked' : (($old['status']==='approved' && $old['enabled']) ? 'approved' : 'pending');
    $con->begin_transaction();
    try {
        es_cdn2_db($con,'INSERT INTO cdn_bash_nodes(id,name,token_hash,status,public_ipv4,location,agent_version,published_state) VALUES (?,?,?,?,?,?,?,?)',
            [$old['node_id'],substr($old['name'],0,64),$status==='revoked' ? null : $old['token_hash'],$status,$ip,$old['location_slug'],(int)$old['version'],es_cdn3_encode($state)]);
        es_cdn2_audit($con,'migration','legacy.import',$old['node_id']);
        $con->commit();
    } catch (Throwable $e) { $con->rollback(); throw $e; }
}
echo "Existing serving configurations are preserved. Recreate legacy assignments under verified zones before drafting a replacement. Issue new enrollment grants in the canonical Admin page.\n";
