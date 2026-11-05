<?php
require_once __DIR__.'/cdn-delivery.php';
require_once __DIR__.'/cdn-deployments.php';
require_once __DIR__.'/cdn-monitoring.php';
/** Bash CDN transport and Cloudflare adapter. Never included on CDN hosts. */
function es_cdn2_db(mysqli $db, string $sql, array $args = []): mysqli_stmt {
    $stmt = $db->prepare($sql);
    $stmt->execute($args);
    return $stmt;
}
function es_cdn2_rows(mysqli $db, string $sql, array $args = []): array {
    return es_cdn2_db($db, $sql, $args)->get_result()->fetch_all(MYSQLI_ASSOC);
}
function es_cdn2_audit(mysqli $db, string $actor, string $action, string $entity): void {
    es_cdn2_db($db, 'INSERT INTO cdn_bash_audit (actor,action,entity) VALUES (?,?,?)', [$actor,$action,$entity]);
}
function es_cdn2_host(string $host, bool $wildcard = false): bool {
    if ($wildcard && str_starts_with($host, '*.')) $host = substr($host, 2);
    return strlen($host) <= 253 && str_contains($host, '.') &&
        preg_match('/^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+$/D', $host) === 1 &&
        count(array_filter(explode('.', $host), fn($label) => strlen($label) > 63)) === 0;
}
function es_cdn2_in_zone(string $host, string $zone): bool {
    $host = str_starts_with($host, '*.') ? substr($host, 2) : $host;
    return $host === $zone || str_ends_with($host, '.' . $zone);
}
function es_cdn2_public_ip(string $ip): bool {
    if (filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE|FILTER_FLAG_GLOBAL_RANGE)===false) return false;
    if (filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)) {
        $n=(int)sprintf('%u',ip2long($ip));
        foreach (['100.64.0.0/10','192.0.0.0/24','192.0.2.0/24','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4'] as $range) {
            [$network,$bits]=explode('/',$range); $mask=(0xffffffff << (32-(int)$bits)) & 0xffffffff;
            if (($n & $mask)===((int)sprintf('%u',ip2long($network)) & $mask)) return false;
        }
        return true;
    }
    // Public IPv6 origins must be global unicast; reject transition/mapped ranges.
    return preg_match('/^[23][0-9a-f]{0,3}:/i',$ip)===1 && !str_starts_with(strtolower($ip),'2001:db8:');
}
function es_cdn2_origin(string $host, array $edgeIps = []): void {
    if (!es_cdn2_host($host)) throw new InvalidArgumentException('Origin must be a lowercase HTTPS hostname without scheme, path or port.');
    $records = dns_get_record($host, DNS_A | DNS_AAAA);
    if (!$records) throw new InvalidArgumentException('Origin has no resolvable public addresses.');
    foreach ($records as $record) {
        $ip = $record['ip'] ?? $record['ipv6'] ?? '';
        if (!es_cdn2_public_ip($ip) || in_array($ip, $edgeIps, true)) throw new InvalidArgumentException('Origin resolves to a private/reserved address or CDN node.');
    }
}
function es_cdn2_rate(mysqli $db, string $key, int $limit): void {
    $bucket = hash('sha256', $key);
    $window = intdiv(time(), 60);
    es_cdn2_db($db, 'INSERT INTO cdn_bash_rate_limits(bucket,window_start,requests) VALUES (?,?,1)
        ON DUPLICATE KEY UPDATE requests=IF(window_start=VALUES(window_start),requests+1,1),window_start=VALUES(window_start)', [$bucket,$window]);
    $row = es_cdn2_rows($db, 'SELECT requests FROM cdn_bash_rate_limits WHERE bucket=?', [$bucket])[0];
    if ((int)$row['requests'] > $limit) throw new RuntimeException('Rate limit exceeded.', 429);
}
function es_cdn2_cf(array $zone, string $method, string $path, ?array $body = null): array {
    if (!preg_match('/^[a-f0-9]{32}$/D', $zone['provider_zone_id'])) throw new RuntimeException('Invalid provider zone ID.');
    if (!preg_match('/^CDN_CF_[A-Z0-9_]{1,80}$/D', $zone['token_env'])) throw new RuntimeException('Invalid provider secret reference.');
    $secret = getenv($zone['token_env']);
    if (!$secret) throw new RuntimeException('DNS provider secret is not configured.');
    $url = 'https://api.cloudflare.com/client/v4/zones/' . $zone['provider_zone_id'] . $path;
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true,CURLOPT_CUSTOMREQUEST=>$method,
        CURLOPT_CONNECTTIMEOUT=>10,CURLOPT_TIMEOUT=>30,CURLOPT_FOLLOWLOCATION=>false,
        CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS,CURLOPT_HTTPHEADER=>['Authorization: Bearer '.$secret,'Content-Type: application/json']]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
    $raw = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($raw === false || $code < 200 || $code >= 300) throw new RuntimeException('DNS provider request failed (HTTP '.$code.').');
    $result = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    if (empty($result['success'])) throw new RuntimeException('DNS provider rejected the request.');
    return $result;
}
function es_cdn2_lock(mysqli $db, string $key): void {
    if ((int)es_cdn2_rows($db, 'SELECT GET_LOCK(?,10) AS acquired', ['cdn_bash_'.$key])[0]['acquired'] !== 1) throw new RuntimeException('Operation in progress; retry.');
}
function es_cdn2_unlock(mysqli $db, string $key): void { es_cdn2_db($db, 'DO RELEASE_LOCK(?)', ['cdn_bash_'.$key]); }
function es_cdn2_dns_create(mysqli $db, array $zone, string $kind, string $name, string $value, ?int $domainId, ?string $nodeId): string {
    $owned = es_cdn2_rows($db, 'SELECT * FROM cdn_bash_dns_records WHERE zone_id=? AND kind=? AND name=? AND content=?', [$zone['id'],$kind,$name,$value]);
    if ($owned) return $owned[0]['provider_record_id'];
    // Recover creation after a provider-success/database-failure using a stable ownership comment.
    $owner = 'EricCDN:' . hash('sha256', $zone['id'].':'.$kind.':'.$name.':'.$value.':'.$domainId.':'.$nodeId);
    $found = es_cdn2_cf($zone, 'GET', '/dns_records?'.http_build_query(['type'=>$kind,'name'=>$name,'per_page'=>100]));
    $record = null;
    foreach ($found['result'] as $candidate) {
        if (($candidate['comment'] ?? '') === $owner && $candidate['content'] === $value) $record = $candidate;
        elseif ($kind === 'A' && !es_cdn2_rows($db,'SELECT id FROM cdn_bash_dns_records WHERE provider_record_id=? AND domain_id=?',[$candidate['id'],$domainId])) throw new RuntimeException('Conflicting/unmanaged DNS record exists; resolve it before publishing.');
    }
    if ($record === null) {
        $record = es_cdn2_cf($zone, 'POST', '/dns_records', ['type'=>$kind,'name'=>$name,'content'=>$value,'ttl'=>120,'proxied'=>false,'comment'=>$owner])['result'];
    }
    if (!preg_match('/^[a-f0-9]{32}$/D', $record['id'])) throw new RuntimeException('Invalid provider record identity.');
    es_cdn2_db($db, 'INSERT INTO cdn_bash_dns_records(zone_id,provider_record_id,domain_id,node_id,kind,name,content) VALUES (?,?,?,?,?,?,?)',
        [$zone['id'],$record['id'],$domainId,$nodeId,$kind,$name,$value]);
    return $record['id'];
}
function es_cdn2_dns_delete(mysqli $db, array $row, array $zone): void {
    // Only touch integration-owned record IDs, and verify they still contain the expected data.
    $records = es_cdn2_cf($zone,'GET','/dns_records?'.http_build_query(['type'=>$row['kind'],'name'=>$row['name'],'per_page'=>100]));
    foreach ($records['result'] as $record) {
        if ($record['id'] !== $row['provider_record_id']) continue;
        if ($record['content'] !== $row['content'] || !str_starts_with($record['comment'] ?? '', 'EricCDN:')) throw new RuntimeException('Managed DNS record changed outside Admin; refusing deletion.');
        es_cdn2_cf($zone,'DELETE','/dns_records/'.$record['id']);
    }
    es_cdn2_db($db,'DELETE FROM cdn_bash_dns_records WHERE id=?',[$row['id']]);
}
function es_cdn2_compile(mysqli $db, array $node): array {
    $domains = [];
    if ($node['status'] === 'approved') {
        $rows = es_cdn2_rows($db, 'SELECT d.* FROM cdn_bash_domains d JOIN cdn_bash_assignments a ON a.domain_id=d.id
            WHERE a.node_id=? AND d.enabled=1 AND (a.draining=0 OR a.drain_until IS NULL OR a.drain_until > UTC_TIMESTAMP()) ORDER BY d.hostname', [$node['id']]);
        foreach ($rows as $d) {
            $domains[] = ['hostname'=>$d['hostname'],'origin'=>$d['origin'],'cache_ttl'=>(int)$d['cache_ttl'],
                'cache_version'=>'v'.$d['cache_version'],'certificate'=>$d['managed_tls'] ? 'd'.$d['id'] : '', 'managed_tls'=>(bool)$d['managed_tls'],
                'policy'=>es_cdn3_policy(json_decode($d['policy_json'] ?? '{}',true,32,JSON_THROW_ON_ERROR),true)];
        }
    }
    return es_cdn3_state($domains);
}
function es_cdn2_desired(mysqli $db, array $node): array {
    if ($node['status']!=='approved') return es_cdn3_state([]);
    if (!empty($node['published_state'])) return es_cdn3_decode($node['published_state']);
    return es_cdn3_state([]);
}

function es_cdn2_register(mysqli $db, string $token, array $body): array {
    $key = getenv('CDN_ENROLLMENT_KEY');
    if (!$key || strlen($key)<32) throw new RuntimeException('Enrollment signing key is not configured.',503);
    if (($body['schema_version'] ?? null)!==1 || ($body['agent'] ?? '')!=='ericcdn-bash' ||
        !preg_match('/^[A-Za-z0-9_-]{1,64}$/D', $body['name'] ?? '') ||
        !preg_match('/^[A-Za-z0-9_-]{16,64}$/D', $body['enrollment_id'] ?? '')) throw new InvalidArgumentException('Invalid enrollment request.');
    $db->begin_transaction();
    try {
        $grant = es_cdn2_rows($db,'SELECT * FROM cdn_bash_enrollments WHERE token_hash=? FOR UPDATE',[hash('sha256',$token)])[0] ?? null;
        if (!$grant || strtotime($grant['expires_at'].' UTC')<time() || $grant['expected_ipv4']!==($_SERVER['REMOTE_ADDR'] ?? '')) throw new RuntimeException('Invalid, expired or address-mismatched enrollment grant.',401);
        if ($grant['node_id'] && $grant['enrollment_id']!==$body['enrollment_id']) throw new RuntimeException('Enrollment grant has already been used.',409);
        $nodeToken = hash_hmac('sha256','node:'.$grant['id'].':'.$body['enrollment_id'],$key);
        if ($grant['node_id']) {
            $node = es_cdn2_rows($db,'SELECT * FROM cdn_bash_nodes WHERE id=?',[$grant['node_id']])[0];
            if ($node['status']==='revoked' || !hash_equals($node['token_hash'] ?? '',hash('sha256',$nodeToken))) throw new RuntimeException('Node credential is revoked.',403);
            $id = $node['id'];
        } else {
            $id = 'cdn_'.bin2hex(random_bytes(12));
            es_cdn2_db($db,'INSERT INTO cdn_bash_nodes(id,name,token_hash,public_ipv4,location) VALUES (?,?,?,?,?)',[$id,$body['name'],hash('sha256',$nodeToken),$grant['expected_ipv4'],$grant['location']]);
            es_cdn2_db($db,'UPDATE cdn_bash_enrollments SET node_id=?,enrollment_id=? WHERE id=?',[$id,$body['enrollment_id'],$grant['id']]);
            es_cdn2_audit($db,'enrollment','node.register',$id);
        }
        $db->commit();
        return ['node_id'=>$id,'node_token'=>$nodeToken];
    } catch (Throwable $e) { $db->rollback(); throw $e; }
}
function es_cdn2_auth(mysqli $db, string $id, string $token): array {
    $node = es_cdn2_rows($db,'SELECT * FROM cdn_bash_nodes WHERE id=? AND token_hash=?',[$id,hash('sha256',$token)])[0] ?? null;
    if (!$node || $node['status']==='revoked') throw new RuntimeException('Invalid node credential.',401);
    return $node;
}
function es_cdn2_challenge(mysqli $db, array $node, string $action, array $body): array {
    if ($node['status']!=='approved') throw new RuntimeException('Node is not approved.',403);
    $name = $body['name'] ?? ''; $value = $body['value'] ?? '';
    if (!is_string($name) || !str_starts_with($name,'_acme-challenge.') || !es_cdn2_host(substr($name,16)) ||
        !is_string($value) || !preg_match('/^[A-Za-z0-9_-]{20,256}$/D',$value)) throw new InvalidArgumentException('Invalid DNS challenge.');
    $host = substr($name,16);
    $domain = es_cdn2_rows($db,'SELECT d.* FROM cdn_bash_domains d JOIN cdn_bash_assignments a ON a.domain_id=d.id
      WHERE a.node_id=? AND d.managed_tls=1 AND (d.hostname=? OR d.hostname=?) LIMIT 1',[$node['id'],$host,'*.'.$host])[0] ?? null;
    if (!$domain) throw new RuntimeException('Challenge is outside this node\'s assignments.',403);
    $zone = es_cdn2_rows($db,'SELECT * FROM cdn_bash_zones WHERE id=?',[$domain['zone_id']])[0];
    es_cdn2_lock($db,'dns');
    try {
        if ($action==='add') {
            if (!$domain['enabled']) throw new RuntimeException('Domain disabled.',403);
            es_cdn2_dns_create($db,$zone,'TXT',$name,$value,(int)$domain['id'],$node['id']);
        } else {
            foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_dns_records WHERE node_id=? AND kind="TXT" AND name=? AND content=?',[$node['id'],$name,$value]) as $record) es_cdn2_dns_delete($db,$record,$zone);
        }
    } finally { es_cdn2_unlock($db,'dns'); }
    return ['ok'=>true];
}
function es_cdn2_reconcile(mysqli $db): array {
    es_cdn2_lock($db,'dns');
    $errors = [];
    try {
        // Remove expired ACME TXT records left by interrupted clients, by owned ID only.
        foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_dns_records WHERE kind="TXT" AND created_at < UTC_TIMESTAMP() - INTERVAL 1 DAY') as $record) {
            try {
                $zone = es_cdn2_rows($db,'SELECT * FROM cdn_bash_zones WHERE id=?',[$record['zone_id']])[0];
                es_cdn2_dns_delete($db,$record,$zone);
            } catch (Throwable $e) { $errors[]='TXT cleanup failed: '.$record['name']; }
        }
        foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_domains ORDER BY id') as $domain) {
            try {
                $zone = es_cdn2_rows($db,'SELECT * FROM cdn_bash_zones WHERE id=?',[$domain['zone_id']])[0];
                $wanted = [];
                $existing = es_cdn2_rows($db,'SELECT * FROM cdn_bash_dns_records WHERE domain_id=? AND kind="A"',[$domain['id']]);
                $existingIps = array_column($existing,'content');
                $nodes = es_cdn2_rows($db,'SELECT n.*,a.draining,a.drain_until FROM cdn_bash_nodes n JOIN cdn_bash_assignments a ON a.node_id=n.id WHERE a.domain_id=?',[$domain['id']]);
                if ($domain['dns_enabled'] && $domain['enabled']) {
                    foreach ($nodes as $node) {
                        $report = json_decode($node['report_json'] ?? '{}',true) ?: [];
                        $fresh = $node['last_seen_at'] && strtotime($node['last_seen_at'].' UTC') > time()-300;
                        if ($node['draining'] || $node['status']!=='approved' || !$fresh || !in_array($report['status'] ?? '',['applied','error'],true)) continue;
                        $desired = es_cdn2_desired($db,$node);
                        if (!($report['metrics']['nginx_up'] ?? false)) continue;
                        // Keep a healthy last-known-good node in DNS while a new revision is pending.
                        if (($report['applied_revision'] ?? '')!==$desired['revision'] && !in_array($node['public_ipv4'],$existingIps,true)) continue;
                        $serves = false;
                        foreach ($desired['domains'] as $d) if ($d['hostname']===$domain['hostname']) $serves=true;
                        if (!$serves) continue;
                        $certReady = false;
                        foreach ($report['metrics']['domains'] ?? [] as $metric) {
                            if (($metric['hostname'] ?? '')===$domain['hostname'] && ((!$domain['managed_tls'] && ($metric['certificate_status'] ?? '')==='http') || in_array($metric['certificate_status'] ?? '',['valid','expiring'],true))) $certReady=true;
                        }
                        if ($certReady) $wanted[$node['public_ipv4']]=$node['id'];
                    }
                }
                // Drain owned DNS records before retiring configurations. TTL=120, plus margin.
                foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_dns_records WHERE domain_id=? AND kind="A"',[$domain['id']]) as $record) {
                    if (!isset($wanted[$record['content']])) es_cdn2_dns_delete($db,$record,$zone);
                }
                foreach ($wanted as $ip=>$nodeId) es_cdn2_dns_create($db,$zone,'A',$domain['hostname'],$ip,(int)$domain['id'],$nodeId);
                es_cdn2_db($db,'UPDATE cdn_bash_assignments SET drain_until=UTC_TIMESTAMP()+INTERVAL 10 MINUTE WHERE domain_id=? AND draining=1 AND drain_until IS NULL',[$domain['id']]);
                es_cdn3_retire_drained($db,(int)$domain['id']);
                es_cdn2_db($db,'UPDATE cdn_bash_domains SET dns_error=NULL WHERE id=?',[$domain['id']]);
            } catch (Throwable $e) {
                $message = substr($e->getMessage(),0,255);
                es_cdn2_db($db,'UPDATE cdn_bash_domains SET dns_error=? WHERE id=?',[$message,$domain['id']]);
                $errors[]=$domain['hostname'].': '.$message;
            }
        }
        es_cdn2_db($db,'DELETE FROM cdn_bash_rate_limits WHERE window_start < ?', [intdiv(time(),60)-1440]);
    } finally { es_cdn2_unlock($db,'dns'); }
    return $errors;
}
function es_cdn2_matches(string $host, string $pattern): bool {
    if (str_starts_with($pattern,'*.')) return str_ends_with($host,substr($pattern,1)) && $host!==substr($pattern,2);
    return $host===$pattern;
}
function es_cdn2_guard_entry_change(mysqli $db, int $uid): void {
    // The additive migration may not yet be installed; legacy entries still work.
    if (!es_cdn2_rows($db,"SHOW TABLES LIKE 'cdn_bash_assignments'")) return;
    if (es_cdn2_rows($db,'SELECT a.node_id FROM cdn_bash_assignments a JOIN cdn_bash_domains d ON d.id=a.domain_id WHERE d.cdn_uid=? LIMIT 1',[$uid])) {
        throw new RuntimeException('Drain this CDN entry\'s Bash assignments in CDN → Bash nodes, reconcile DNS, and wait ten minutes before disabling/deleting the entry.');
    }
}
