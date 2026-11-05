<?php
require_once __DIR__.'/../bootstrap.php';
require_once __DIR__.'/../../includes/cdn-bash.php';
admin_verify_post();
$actor = is_string($adminUser) ? $adminUser : (string)($adminUser['username'] ?? 'admin');
$action = (string)($_POST['operation'] ?? '');
try {
    switch ($action) {
        case 'draft':
            es_cdn3_draft($con,trim((string)($_POST['title'] ?? '')),$actor);
            break;
        case 'deploy':
            es_cdn3_deploy($con,(int)($_POST['deployment_id'] ?? 0),(string)($_POST['deploy_action'] ?? ''),$actor,(string)($_POST['canary_node'] ?? ''));
            break;
        case 'ack':
            es_cdn2_db($con,'UPDATE cdn_bash_alerts SET acknowledged_at=UTC_TIMESTAMP() WHERE fingerprint=?',[(string)($_POST['fingerprint'] ?? '')]);
            break;
        case 'sign':
            $domain=es_cdn2_rows($con,'SELECT * FROM cdn_bash_domains WHERE id=?',[(int)($_POST['domain_id'] ?? 0)])[0] ?? null;
            if (!$domain) throw new InvalidArgumentException('Domain not found.');
            $host=(string)($_POST['download_host'] ?? $domain['hostname']);
            if (!es_cdn2_matches($host,$domain['hostname'])) throw new InvalidArgumentException('Download hostname is outside this assignment.');
            $keys=[];
            foreach (es_cdn2_rows($con,'SELECT * FROM cdn_bash_nodes WHERE status="approved"') as $node) {
                foreach (es_cdn2_desired($con,$node)['domains'] as $liveDomain) if ($liveDomain['hostname']===$domain['hostname']) $keys[]=$liveDomain['policy']['signing_key'] ?? '';
            }
            $keys=array_values(array_unique($keys));
            if (count($keys)!==1 || $keys[0]==='') throw new RuntimeException('Finish publishing the signing policy consistently to all hosts before generating a download link.');
            $_SESSION['cdn_signed_link']=es_cdn3_sign($host,(string)($_POST['download_path'] ?? ''),es_cdn3_post_int($_POST['download_ttl'] ?? 3600),$keys[0]);
            es_cdn2_audit($con,$actor,'download.sign',$host);
            break;
        case 'grant':
            $ip = trim((string)($_POST['public_ipv4'] ?? ''));
            if (!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) || !es_cdn2_public_ip($ip)) throw new InvalidArgumentException('Use the node\'s public IPv4 (also its enrollment source address).');
            $location = trim((string)($_POST['location'] ?? ''));
            if (strlen($location)>100) throw new InvalidArgumentException('Location is too long.');
            if (strlen(getenv('CDN_ENROLLMENT_KEY') ?: '')<32) throw new RuntimeException('Configure CDN_ENROLLMENT_KEY first.');
            $token = bin2hex(random_bytes(32));
            es_cdn2_db($con,'INSERT INTO cdn_bash_enrollments(token_hash,expected_ipv4,location,expires_at,created_by) VALUES (?,?,?,UTC_TIMESTAMP()+INTERVAL 1 HOUR,?)',[hash('sha256',$token),$ip,$location,$actor]);
            $_SESSION['cdn_bash_grant']=$token;
            es_cdn2_audit($con,$actor,'enrollment.create',$ip);
            break;
        case 'node':
            $id = (string)($_POST['node_id'] ?? '');
            $state = (string)($_POST['state'] ?? '');
            $node = es_cdn2_rows($con,'SELECT * FROM cdn_bash_nodes WHERE id=?',[$id])[0] ?? null;
            if (!$node || $node['status']==='revoked') throw new InvalidArgumentException('Node missing or revoked.');
            if ($state==='drain') {
                es_cdn2_db($con,'UPDATE cdn_bash_assignments SET draining=1,drain_until=NULL WHERE node_id=?',[$id]);
            } elseif (in_array($state,['approved','disabled','revoked'],true)) {
                if ($state!=='approved' && !empty(es_cdn2_desired($con,$node)['domains'])) throw new InvalidArgumentException('Publish removal of this host\'s domains and wait for activation before disabling/revoking.');
                if ($state!=='approved' && es_cdn2_rows($con,'SELECT node_id FROM cdn_bash_assignments WHERE node_id=?',[$id])) throw new InvalidArgumentException('Drain this node, wait for DNS reconciliation and TTL expiry, then disable/revoke.');
                es_cdn2_db($con,'UPDATE cdn_bash_nodes SET status=?,token_hash=IF(?="revoked",NULL,token_hash) WHERE id=?',[$state,$state,$id]);
            } else throw new InvalidArgumentException('Invalid node operation.');
            es_cdn2_audit($con,$actor,'node.'.$state,$id);
            break;
        case 'zone':
            $name = strtolower(trim((string)($_POST['name'] ?? '')));
            $provider = trim((string)($_POST['provider_zone_id'] ?? ''));
            $secret = trim((string)($_POST['token_env'] ?? ''));
            if (!es_cdn2_host($name)) throw new InvalidArgumentException('Invalid DNS zone.');
            $existingZone=es_cdn2_rows($con,'SELECT * FROM cdn_bash_zones WHERE name=?',[$name])[0] ?? null;
            if ($existingZone && $existingZone['provider_zone_id']!==$provider) throw new InvalidArgumentException('Zone provider identity is immutable; migrate owned records before moving the zone.');
            $zone = ['provider_zone_id'=>$provider,'token_env'=>$secret];
            $verified = es_cdn2_cf($zone,'GET','')['result'];
            if (($verified['name'] ?? '')!==$name || ($verified['status'] ?? '')!=='active') throw new InvalidArgumentException('Provider zone is not active or its name differs.');
            es_cdn2_db($con,'INSERT INTO cdn_bash_zones(name,provider_zone_id,token_env) VALUES (?,?,?) ON DUPLICATE KEY UPDATE provider_zone_id=VALUES(provider_zone_id),token_env=VALUES(token_env)',[$name,$provider,$secret]);
            es_cdn2_audit($con,$actor,'zone.verify',$name);
            break;
        case 'domain':
            $id = (int)($_POST['domain_id'] ?? 0);
            $uid = (int)($_POST['cdn_uid'] ?? 0);
            $zone = es_cdn2_rows($con,'SELECT * FROM cdn_bash_zones WHERE id=?',[(int)($_POST['zone_id'] ?? 0)])[0] ?? null;
            $cdn = es_cdn2_rows($con,'SELECT * FROM cdn WHERE uid=?',[$uid])[0] ?? null;
            if (!$cdn || ($cdn['status'] ?? '')!=='active' || !$zone) throw new InvalidArgumentException('Select an active CDN entry and a verified zone.');
            $host = strtolower(trim((string)($_POST['hostname'] ?? '')));
            $origin = strtolower(trim((string)($_POST['origin'] ?? '')));
            $ttl = filter_var($_POST['cache_ttl'] ?? '',FILTER_VALIDATE_INT,['options'=>['min_range'=>0,'max_range'=>604800]]);
            if (!es_cdn2_host($host,true) || !es_cdn2_in_zone($host,$zone['name']) || $ttl===false) throw new InvalidArgumentException('Invalid hostname, zone or cache TTL.');
            foreach (es_cdn2_rows($con,'SELECT hostname FROM cdn_bash_domains') as $other) {
                if (es_cdn2_matches($origin,$other['hostname'])) throw new InvalidArgumentException('Origin points to a managed CDN hostname.');
            }
            if (es_cdn2_matches($origin,$host)) throw new InvalidArgumentException('Origin would loop through this CDN.');
            es_cdn2_origin($origin,array_column(es_cdn2_rows($con,'SELECT public_ipv4 FROM cdn_bash_nodes'),'public_ipv4'));
            $policy=es_cdn3_policy_post($_POST);
            $edgeIps=array_column(es_cdn2_rows($con,'SELECT public_ipv4 FROM cdn_bash_nodes'),'public_ipv4');
            foreach ($policy['backup_origins'] as $backup) {
                es_cdn2_origin($backup,$edgeIps);
                if (es_cdn2_matches($backup,$host)) throw new InvalidArgumentException('Backup origin loops through this CDN hostname.');
                foreach (es_cdn2_rows($con,'SELECT hostname FROM cdn_bash_domains') as $other) if (es_cdn2_matches($backup,$other['hostname'])) throw new InvalidArgumentException('Backup origin points to a CDN hostname.');
            }
            $policyJson=json_encode($policy,JSON_THROW_ON_ERROR);
            $tls = isset($_POST['managed_tls']) ? 1 : 0;
            if (!$tls && $policy['signed_url_env']!=='') throw new InvalidArgumentException('Signed downloads require managed HTTPS.');
            $dns = isset($_POST['dns_enabled']) ? 1 : 0;
            $nodeIds = $_POST['node_ids'] ?? [];
            if (!is_array($nodeIds) || count($nodeIds)>100) throw new InvalidArgumentException('Invalid node selection.');
            $nodeIds = array_values(array_unique(array_map('strval',$nodeIds)));
            foreach ($nodeIds as $nodeId) {
                if (!es_cdn2_rows($con,'SELECT id FROM cdn_bash_nodes WHERE id=? AND status="approved"',[$nodeId])) throw new InvalidArgumentException('Only approved nodes may be assigned.');
                if (count(es_cdn2_rows($con,'SELECT domain_id FROM cdn_bash_assignments WHERE node_id=? AND domain_id<>?',[$nodeId,$id]))>=100) throw new InvalidArgumentException('Node has reached the 100-domain limit.');
            }
            $con->begin_transaction();
            try {
                if ($id) {
                    $old = es_cdn2_rows($con,'SELECT * FROM cdn_bash_domains WHERE id=? FOR UPDATE',[$id])[0] ?? null;
                    if (!$old || $old['hostname']!==$host || (int)$old['zone_id']!==(int)$zone['id'] || (int)$old['cdn_uid']!==$uid) throw new InvalidArgumentException('Hostname, owner CDN entry and zone are immutable; create a new assignment to change them.');
                    es_cdn2_db($con,'UPDATE cdn_bash_domains SET origin=?,cache_ttl=?,managed_tls=?,dns_enabled=? WHERE id=?',[$origin,$ttl,$tls,$dns,$id]);
                } else {
                    es_cdn2_db($con,'INSERT INTO cdn_bash_domains(cdn_uid,zone_id,hostname,origin,cache_ttl,managed_tls,dns_enabled) VALUES (?,?,?,?,?,?,?)',[$uid,$zone['id'],$host,$origin,$ttl,$tls,$dns]);
                    $id = $con->insert_id;
                }
                foreach (es_cdn2_rows($con,'SELECT node_id FROM cdn_bash_assignments WHERE domain_id=?',[$id]) as $assignment) {
                    if (!in_array($assignment['node_id'],$nodeIds,true)) es_cdn2_db($con,'UPDATE cdn_bash_assignments SET draining=1,drain_until=NULL WHERE domain_id=? AND node_id=? AND draining=0',[$id,$assignment['node_id']]);
                }
                foreach ($nodeIds as $nodeId) es_cdn2_db($con,'INSERT INTO cdn_bash_assignments(node_id,domain_id) VALUES (?,?) ON DUPLICATE KEY UPDATE draining=0,drain_until=NULL',[$nodeId,$id]);
                es_cdn2_db($con,'UPDATE cdn_bash_domains SET policy_json=? WHERE id=?',[$policyJson,$id]);
                es_cdn2_audit($con,$actor,'domain.save',$host);
                $con->commit();
            } catch (Throwable $e) { $con->rollback(); throw $e; }
            break;
        case 'purge':
            $id = (int)($_POST['domain_id'] ?? 0);
            es_cdn2_db($con,'UPDATE cdn_bash_domains SET cache_version=cache_version+1 WHERE id=?',[$id]);
            es_cdn2_audit($con,$actor,'cache.invalidate',(string)$id);
            break;
        case 'retire':
            $id = (int)($_POST['domain_id'] ?? 0);
            es_cdn2_db($con,'UPDATE cdn_bash_domains SET dns_enabled=0 WHERE id=?',[$id]);
            es_cdn2_db($con,'UPDATE cdn_bash_assignments SET draining=1,drain_until=NULL WHERE domain_id=? AND draining=0',[$id]);
            es_cdn2_audit($con,$actor,'domain.drain',(string)$id);
            break;
        case 'reconcile':
            $errors = es_cdn2_reconcile($con);
            es_cdn3_monitor($con);
            if ($errors) throw new RuntimeException(implode('; ',array_slice($errors,0,3)));
            es_cdn2_audit($con,$actor,'dns.reconcile','all');
            break;
        default: throw new InvalidArgumentException('Unknown operation.');
    }
    es_admin_redirect('/admin/cdn-bash.php','success','CDN change saved. Domain edits require a configuration draft and publication; published changes apply on the next poll.');
} catch (Throwable $e) {
    // Database exceptions contain implementation details, not user-facing diagnostics.
    $message = $e instanceof mysqli_sql_exception ? 'Database operation failed; check migration and duplicate entries.' : $e->getMessage();
    es_admin_redirect('/admin/cdn-bash.php','error',$message);
}
