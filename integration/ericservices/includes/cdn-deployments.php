<?php
function es_cdn3_config_key(): string {
    if (!function_exists('sodium_crypto_secretbox')) throw new RuntimeException('PHP sodium is required for configuration snapshots.');
    $key=getenv('CDN_ENROLLMENT_KEY');
    if (!$key || strlen($key)<32) throw new RuntimeException('Configure the stable CDN_ENROLLMENT_KEY before publishing.');
    return hash('sha256','EricCDN configuration snapshots:'.$key,true);
}
function es_cdn3_encode(array $state): string {
    $key=es_cdn3_config_key();
    $nonce=random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return 'v1:'.base64_encode($nonce.sodium_crypto_secretbox(json_encode($state,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES),$nonce,$key));
}
function es_cdn3_decode(string $blob): array {
    if (!str_starts_with($blob,'v1:')) return json_decode($blob,true,64,JSON_THROW_ON_ERROR);
    $data=base64_decode(substr($blob,3),true);
    if ($data===false || strlen($data)<=SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) throw new RuntimeException('Corrupt configuration snapshot.');
    $json=sodium_crypto_secretbox_open(substr($data,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),substr($data,0,SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),es_cdn3_config_key());
    if ($json===false) throw new RuntimeException('Snapshot key is unavailable or snapshot was modified.');
    return json_decode($json,true,64,JSON_THROW_ON_ERROR);
}
function es_cdn3_draft(mysqli $db,string $title,string $actor): int {
    if ($title==='' || strlen($title)>120) throw new InvalidArgumentException('A deployment title of 1–120 characters is required.');
    es_cdn2_lock($db,'deployment'); $db->begin_transaction();
    try {
        $nodes=es_cdn2_rows($db,'SELECT * FROM cdn_bash_nodes WHERE status="approved" ORDER BY id');
        if (!$nodes) throw new RuntimeException('Approve at least one host before creating a draft.');
        es_cdn2_db($db,'INSERT INTO cdn_bash_deployments(title,actor) VALUES (?,?)',[$title,$actor]);
        $id=$db->insert_id;
        foreach ($nodes as $node) {
            if ((int)($node['agent_version'] ?? 2)<3) throw new RuntimeException('Upgrade hosts to EricCDN agent version 3 and wait for a health report before drafting.');
            $state=es_cdn2_compile($db,$node);
            $report=json_decode($node['report_json'] ?? '{}',true) ?: [];
            foreach ($state['domains'] as $domain) if (!empty($domain['policy']['signing_key']) && empty($report['metrics']['capabilities']['secure_link'])) throw new RuntimeException('Signed downloads require nginx secure_link support on every assigned host.');
            if (count($state['domains'])>100) throw new RuntimeException('Host domain limit exceeded.');
            es_cdn2_db($db,'INSERT INTO cdn_bash_snapshots(deployment_id,node_id,desired_json,previous_json,previous_deployment_id) VALUES (?,?,?,?,?)',
                [$id,$node['id'],es_cdn3_encode($state),es_cdn3_encode(es_cdn2_desired($db,$node)),$node['deployment_id']]);
        }
        es_cdn2_audit($db,$actor,'deployment.draft',(string)$id);
        $db->commit(); return $id;
    } catch (Throwable $e) { $db->rollback(); throw $e; }
    finally { es_cdn2_unlock($db,'deployment'); }
}
function es_cdn3_canary_ready(mysqli $db,array $deployment): void {
    $node=es_cdn2_rows($db,'SELECT * FROM cdn_bash_nodes WHERE id=?',[$deployment['canary_node']])[0] ?? null;
    if (!$node || $node['status']!=='approved' || (int)$node['deployment_id']!==(int)$deployment['id']) throw new RuntimeException('Canary host is unavailable or was changed by another deployment.');
    $desired=es_cdn2_desired($db,$node); $report=json_decode($node['report_json'] ?? '{}',true) ?: [];
    if (!$node['last_seen_at'] || strtotime($node['last_seen_at'].' UTC')<time()-300 || ($report['status'] ?? '')!=='applied' ||
        ($report['applied_revision'] ?? '')!==$desired['revision'] || !($report['metrics']['nginx_up'] ?? false)) throw new RuntimeException('Wait for the canary to report successful activation.');
    foreach ($desired['domains'] as $domain) {
        $probe=es_cdn2_rows($db,'SELECT * FROM cdn_bash_probes WHERE node_id=? AND hostname=?',[$node['id'],$domain['hostname']])[0] ?? null;
        if (!$probe || (int)$probe['failures']>0 || $probe['revision']!==$desired['revision'] || strtotime($probe['checked_at'].' UTC')<time()-300) throw new RuntimeException('Wait for the canary\'s external domain checks to pass.');
    }
}
function es_cdn3_deploy(mysqli $db,int $id,string $operation,string $actor,string $canary=''): void {
    es_cdn2_lock($db,'deployment'); $db->begin_transaction();
    try {
        $deployment=es_cdn2_rows($db,'SELECT * FROM cdn_bash_deployments WHERE id=? FOR UPDATE',[$id])[0] ?? null;
        if (!$deployment) throw new InvalidArgumentException('Deployment not found.');
        if ($operation==='canary' && $deployment['status']!=='draft') throw new RuntimeException('Only drafts can start a canary.');
        if ($operation==='promote') {
            if ($deployment['status']!=='canary') throw new RuntimeException('Start a canary before promotion.');
            es_cdn3_canary_ready($db,$deployment);
        }
        if ($operation==='rollback' && !in_array($deployment['status'],['canary','published'],true)) throw new RuntimeException('This deployment is not active.');
        if (!in_array($operation,['canary','promote','rollback'],true)) throw new InvalidArgumentException('Unknown deployment operation.');
        $rows=es_cdn2_rows($db,'SELECT * FROM cdn_bash_snapshots WHERE deployment_id=? ORDER BY node_id',[$id]);
        if ($operation==='canary' && !in_array($canary,array_column($rows,'node_id'),true)) throw new InvalidArgumentException('Select a host contained in this draft.');
        foreach ($rows as $snapshot) {
            if ($operation==='canary' && $snapshot['node_id']!==$canary) continue;
            if ($operation==='promote' && $snapshot['activated']) continue;
            if ($operation==='rollback' && !$snapshot['activated']) continue;
            $node=es_cdn2_rows($db,'SELECT * FROM cdn_bash_nodes WHERE id=? FOR UPDATE',[$snapshot['node_id']])[0];
            if ($node['status']!=='approved') throw new RuntimeException('A selected host is no longer approved. Create a new draft.');
            if ($operation==='rollback') {
                if ((int)$node['deployment_id']!==$id) throw new RuntimeException('A newer deployment changed this host; roll that deployment back first.');
                $state=es_cdn3_decode($snapshot['previous_json']);
                es_cdn2_db($db,'UPDATE cdn_bash_nodes SET published_state=?,deployment_id=? WHERE id=?',[es_cdn3_encode($state),$snapshot['previous_deployment_id'],$node['id']]);
            } else {
                $previous=es_cdn3_decode($snapshot['previous_json']); $current=es_cdn2_desired($db,$node);
                if ($previous['revision']!==$current['revision'] || ($node['deployment_id'] ?? null)!==($snapshot['previous_deployment_id'] ?? null)) throw new RuntimeException('Draft is stale because a host changed. Create another draft.');
                es_cdn2_db($db,'UPDATE cdn_bash_nodes SET published_state=?,deployment_id=? WHERE id=?',[$snapshot['desired_json'],$id,$node['id']]);
                es_cdn2_db($db,'UPDATE cdn_bash_snapshots SET activated=1 WHERE deployment_id=? AND node_id=?',[$id,$node['id']]);
            }
        }
        $status=match($operation) {'canary'=>'canary','promote'=>'published',default=>'rolled_back'};
        es_cdn2_db($db,'UPDATE cdn_bash_deployments SET status=?,canary_node=COALESCE(NULLIF(?,""),canary_node) WHERE id=?',[$status,$canary,$id]);
        es_cdn2_audit($db,$actor,'deployment.'.$operation,(string)$id);
        $db->commit();
    } catch (Throwable $e) { $db->rollback(); throw $e; }
    finally { es_cdn2_unlock($db,'deployment'); }
}
function es_cdn3_retire_drained(mysqli $db,int $domainId): void {
    $expired=es_cdn2_rows($db,'SELECT a.node_id,d.hostname FROM cdn_bash_assignments a JOIN cdn_bash_domains d ON d.id=a.domain_id WHERE a.domain_id=? AND a.draining=1 AND a.drain_until<UTC_TIMESTAMP()',[$domainId]);
    if (!$expired) return;
    es_cdn2_lock($db,'deployment'); $db->begin_transaction();
    try {
        foreach ($expired as $assignment) {
            $node=es_cdn2_rows($db,'SELECT * FROM cdn_bash_nodes WHERE id=? FOR UPDATE',[$assignment['node_id']])[0];
            $before=es_cdn2_desired($db,$node);
            $domains=array_values(array_filter($before['domains'],fn($d)=>$d['hostname']!==$assignment['hostname']));
            if (count($domains)===count($before['domains'])) continue;
            $after=es_cdn3_state($domains);
            es_cdn2_db($db,'INSERT INTO cdn_bash_deployments(title,actor,status) VALUES (?,"system:drain","published")',['Drain retirement: '.$assignment['hostname']]);
            $id=$db->insert_id;
            es_cdn2_db($db,'INSERT INTO cdn_bash_snapshots(deployment_id,node_id,desired_json,previous_json,previous_deployment_id,activated) VALUES (?,?,?,?,?,1)',[$id,$node['id'],es_cdn3_encode($after),es_cdn3_encode($before),$node['deployment_id']]);
            es_cdn2_db($db,'UPDATE cdn_bash_nodes SET published_state=?,deployment_id=? WHERE id=?',[es_cdn3_encode($after),$id,$node['id']]);
            es_cdn2_audit($db,'system:drain','domain.retired',$assignment['hostname']);
        }
        es_cdn2_db($db,'DELETE FROM cdn_bash_assignments WHERE domain_id=? AND draining=1 AND drain_until<UTC_TIMESTAMP()',[$domainId]);
        $db->commit();
    } catch(Throwable $e) { $db->rollback(); throw $e; }
    finally { es_cdn2_unlock($db,'deployment'); }
}
function es_cdn3_ready(mysqli $db): bool {
    return (es_cdn2_rows($db,'SELECT value FROM cdn_bash_settings WHERE name="deployment_ready"')[0]['value'] ?? '')==='1';
}
