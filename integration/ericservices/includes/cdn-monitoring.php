<?php
function es_cdn3_alert(mysqli $db,string $node,string $kind,string $message,string $severity='warning',bool $active=true): void {
    $fingerprint=hash('sha256',$node.':'.$kind);
    if (!$active) { es_cdn2_db($db,'UPDATE cdn_bash_alerts SET resolved_at=UTC_TIMESTAMP() WHERE fingerprint=? AND resolved_at IS NULL',[$fingerprint]); return; }
    es_cdn2_db($db,'INSERT INTO cdn_bash_alerts(fingerprint,node_id,kind,severity,message) VALUES (?,?,?,?,?)
      ON DUPLICATE KEY UPDATE acknowledged_at=IF(resolved_at IS NOT NULL,NULL,acknowledged_at),opened_at=IF(resolved_at IS NOT NULL,UTC_TIMESTAMP(),opened_at),resolved_at=NULL,updated_at=UTC_TIMESTAMP(),message=VALUES(message),severity=VALUES(severity)',[$fingerprint,$node,$kind,$severity,$message]);
}
function es_cdn3_report(mysqli $db,array $node,array $body): void {
    $m=$body['metrics'] ?? [];
    if (!is_array($m) || !is_array($m['domains'] ?? null) || count($m['domains'])>100) throw new InvalidArgumentException('Invalid report metrics.');
    $seconds=$m['interval_seconds'] ?? 60;
    es_cdn3_int($seconds,1,604800);
    $totalRequests=0; $totalErrors=0;
    foreach ($m['domains'] as $domain) {
        if (!is_array($domain) || !es_cdn2_host($domain['hostname'] ?? '',true)) throw new InvalidArgumentException('Invalid metric hostname.');
        foreach (['requests','bytes','cache_hits','errors_5xx'] as $field) es_cdn3_int($domain[$field] ?? 0,0,PHP_INT_MAX);
        $latency=$domain['origin_latency_ms'] ?? 0;
        if (!is_numeric($latency) || !is_finite((float)$latency) || $latency<0 || $latency>3600000) throw new InvalidArgumentException('Invalid origin latency.');
        es_cdn2_db($db,'INSERT INTO cdn_bash_metric_history(node_id,hostname,interval_seconds,requests,bytes,hits,errors,origin_latency_ms) VALUES (?,?,?,?,?,?,?,?)',
            [$node['id'],$domain['hostname'],$seconds,$domain['requests'] ?? 0,$domain['bytes'] ?? 0,$domain['cache_hits'] ?? 0,$domain['errors_5xx'] ?? 0,$latency]);
        $totalRequests+=$domain['requests'] ?? 0; $totalErrors+=$domain['errors_5xx'] ?? 0;
        $days=$domain['certificate_days'] ?? null;
        $certAlert=is_numeric($days) && (float)$days<14;
        es_cdn3_alert($db,$node['id'],'cert:'.$domain['hostname'],'Certificate expires in '.(int)$days.' days: '.$domain['hostname'],is_numeric($days) && $days<3 ? 'critical' : 'warning',$certAlert);
    }
    $free=$m['disk_free_bytes'] ?? PHP_INT_MAX; $capacity=$m['disk_total_bytes'] ?? 0;
    if (!is_numeric($free) || !is_numeric($capacity) || $free<0 || $capacity<0) throw new InvalidArgumentException('Invalid disk metrics.');
    es_cdn3_alert($db,$node['id'],'disk','CDN disk space is low.','critical',$free<1073741824 || ($capacity>0 && $free/$capacity<0.1));
    es_cdn3_alert($db,$node['id'],'nginx','nginx is not running.','critical',is_bool($m['nginx_up'] ?? null) && $m['nginx_up']===false);
    es_cdn3_alert($db,$node['id'],'sync','Configuration synchronization failed.','warning',($body['status'] ?? '')==='error');
    es_cdn3_alert($db,$node['id'],'errors','More than 5% of recent requests returned 5xx.','warning',$totalRequests>=20 && $totalErrors/$totalRequests>0.05);
    es_cdn3_alert($db,$node['id'],'upgrade','Upgrade this host to agent version 3 for delivery policies and telemetry.','warning',($m['agent_version'] ?? 1)<3);
    $version=is_int($m['agent_version'] ?? null) ? $m['agent_version'] : 2;
    es_cdn2_db($db,'UPDATE cdn_bash_nodes SET agent_version=? WHERE id=?',[min(100,max(1,$version)),$node['id']]);
}
function es_cdn3_probe(array $node,array $domain,string $revision): array {
    if (!es_cdn2_public_ip($node['public_ipv4'])) throw new RuntimeException('Probe address is not public.');
    $host=str_starts_with($domain['hostname'],'*.') ? 'health.'.substr($domain['hostname'],2) : $domain['hostname'];
    if (!es_cdn2_host($host)) throw new RuntimeException('Invalid probe hostname.');
    $tls=!empty($domain['certificate']); $port=$tls ? 443 : 80;
    $ch=curl_init(($tls ? 'https' : 'http').'://'.$host.'/_ericcdn_health');
    $received='';
    curl_setopt_array($ch,[CURLOPT_RETURNTRANSFER=>false,CURLOPT_FOLLOWLOCATION=>false,CURLOPT_CONNECTTIMEOUT=>3,CURLOPT_TIMEOUT=>5,
      CURLOPT_PROTOCOLS=>CURLPROTO_HTTP|CURLPROTO_HTTPS,CURLOPT_PROXY=>'',CURLOPT_RESOLVE=>[$host.':'.$port.':'.$node['public_ipv4']],
      CURLOPT_WRITEFUNCTION=>function($ch,$chunk) use (&$received) { if(strlen($received)+strlen($chunk)>1024) return 0; $received.=$chunk; return strlen($chunk); }]);
    curl_exec($ch); $code=(int)curl_getinfo($ch,CURLINFO_HTTP_CODE); $latency=curl_getinfo($ch,CURLINFO_TOTAL_TIME)*1000; curl_close($ch);
    return ['ok'=>$code===200 && $received===$revision,'status_code'=>$code,'latency_ms'=>$latency];
}
function es_cdn3_monitor(mysqli $db): void {
    es_cdn2_lock($db,'monitor');
    try {
        $budget=50;
        foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_nodes WHERE status="approved" ORDER BY COALESCE(last_probe_at,"1970-01-01"),id') as $node) {
            $stale=!$node['last_seen_at'] || strtotime($node['last_seen_at'].' UTC')<time()-300;
            es_cdn3_alert($db,$node['id'],'stale','No host report received for five minutes.','critical',$stale);
            $desired=es_cdn2_desired($db,$node);
            $previous=[];
            foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_probes WHERE node_id=? ORDER BY checked_at',[$node['id']]) as $p) $previous[$p['hostname']]=$p;
            usort($desired['domains'],fn($a,$b)=>strcmp($previous[$a['hostname']]['checked_at'] ?? '',$previous[$b['hostname']]['checked_at'] ?? ''));
            $probed=false;
            foreach ($desired['domains'] as $domain) {
                if ($budget--<=0) break;
                $probed=true;
                $result=es_cdn3_probe($node,$domain,$desired['revision']);
                $old=$previous[$domain['hostname']] ?? null;
                $failures=$result['ok'] ? 0 : 1+(int)($old['failures'] ?? 0);
                es_cdn2_db($db,'INSERT INTO cdn_bash_probes(node_id,hostname,checked_at,status_code,revision,latency_ms,failures) VALUES (?,?,UTC_TIMESTAMP(),?,?,?,?)
                  ON DUPLICATE KEY UPDATE checked_at=UTC_TIMESTAMP(),status_code=VALUES(status_code),revision=VALUES(revision),latency_ms=VALUES(latency_ms),failures=VALUES(failures)',
                  [$node['id'],$domain['hostname'],$result['status_code'],$desired['revision'],$result['latency_ms'],$failures]);
                es_cdn3_alert($db,$node['id'],'probe:'.$domain['hostname'],'External availability check failed: '.$domain['hostname'],'critical',$failures>=2);
            }
            if ($probed) es_cdn2_db($db,'UPDATE cdn_bash_nodes SET last_probe_at=UTC_TIMESTAMP() WHERE id=?',[$node['id']]);
        }
        foreach(es_cdn2_rows($db,'SELECT hostname,dns_error FROM cdn_bash_domains') as $d) es_cdn3_alert($db,'system','dns:'.$d['hostname'],'DNS reconciliation failed for '.$d['hostname'],'warning',!empty($d['dns_error']));
        es_cdn2_db($db,'DELETE FROM cdn_bash_metric_history WHERE received_at < UTC_TIMESTAMP()-INTERVAL 7 DAY');
        es_cdn2_db($db,'DELETE FROM cdn_bash_alerts WHERE resolved_at < UTC_TIMESTAMP()-INTERVAL 30 DAY');
    } finally { es_cdn2_unlock($db,'monitor'); }
}
