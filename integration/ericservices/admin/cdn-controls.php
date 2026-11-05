<?php
function cdn3_field(string $name,string $label,mixed $value='',string $type='text'): void {
    echo '<label class="text-sm">'.cdn_h($label).'<input class="block w-full rounded border p-2" name="'.cdn_h($name).'" type="'.cdn_h($type).'" value="'.cdn_h($value).'"></label>';
}
function cdn3_select(string $name,string $label,array $options,mixed $selected): void {
    echo '<label class="text-sm">'.cdn_h($label).'<select class="block rounded border p-2" name="'.cdn_h($name).'">';
    foreach ($options as $value=>$text) echo '<option value="'.cdn_h($value).'"'.((string)$selected===(string)$value ? ' selected' : '').'>'.cdn_h($text).'</option>';
    echo '</select></label>';
}
function cdn3_rules(string $kind,string $label,array $rows): void {
    echo '<fieldset class="my-3 w-full rounded border p-3"><legend>'.cdn_h($label).'</legend><div data-rule-list="'.cdn_h($kind).'">';
    foreach (array_merge($rows,[[]]) as $i=>$row) {
        echo '<div class="my-2 flex flex-wrap gap-2" data-rule-row>';
        $prefix=$kind.'['.$i.']';
        if ($kind==='cache_rules') {
            cdn3_select($prefix.'[match]','Match',['prefix'=>'Path prefix','exact'=>'Exact path','extension'=>'File extension'],$row['match'] ?? 'prefix');
            cdn3_field($prefix.'[value]','Path or extension',$row['value'] ?? ''); cdn3_field($prefix.'[ttl]','TTL seconds (0 bypasses cache)',$row['ttl'] ?? 3600,'number');
        } elseif ($kind==='redirects') {
            cdn3_field($prefix.'[path]','Exact source path',$row['path'] ?? ''); cdn3_field($prefix.'[target]','Destination path or HTTPS URL',$row['target'] ?? '');
            cdn3_select($prefix.'[code]','HTTP status',[301=>'301 permanent',302=>'302 temporary',307=>'307 temporary',308=>'308 permanent'],$row['code'] ?? 302);
        } else {
            cdn3_select($prefix.'[name]','Response header',array_combine(['X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Content-Security-Policy','Access-Control-Expose-Headers','X-Robots-Tag'],['X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Content-Security-Policy','Access-Control-Expose-Headers','X-Robots-Tag']),$row['name'] ?? 'X-Content-Type-Options');
            cdn3_field($prefix.'[value]','Header value',$row['value'] ?? '');
        }
        echo '<button type="button" class="text-red-700" onclick="cdnRemoveRule(this)">Remove rule</button></div>';
    }
    echo '</div><button type="button" class="text-brand-blue" onclick="cdnAddRule(\''.cdn_h($kind).'\')">Add rule</button></fieldset>';
}
function cdn3_policy_fields(array $edit): void {
    $p=es_cdn3_policy(json_decode($edit['policy_json'] ?? '{}',true) ?: []);
    echo '<fieldset class="w-full rounded border p-4"><legend class="font-semibold">Delivery and origin resilience</legend><div class="grid gap-3 sm:grid-cols-3">';
    cdn3_field('connect_timeout','Connect timeout (seconds)',$p['connect_timeout'],'number'); cdn3_field('read_timeout','Read timeout (seconds)',$p['read_timeout'],'number');
    cdn3_select('query_string','Cache query strings',['include'=>'Include query string','ignore'=>'Ignore query string'],$p['query_string']);
    cdn3_field('cors_origin','Allowed CORS origin (empty, *, or HTTPS origin)',$p['cors_origin']);
    cdn3_select('download','Download behavior',[''=>'Follow origin','inline'=>'Display inline','attachment'=>'Download attachment'],$p['download']);
    echo '</div><label class="my-3 block"><input type="checkbox" name="serve_stale" value="1"'.($p['serve_stale'] ? ' checked' : '').'> Serve stale cached content during origin failure/background refresh</label><label class="block text-sm">Backup HTTPS origin hostnames, one per line (up to three)<textarea class="block w-full rounded border p-2" name="backup_origins">'.cdn_h(implode("\n",$p['backup_origins'])).'</textarea></label>';
    cdn3_rules('cache_rules','Cache rules',$p['cache_rules']); cdn3_rules('redirects','Redirects',$p['redirects']); cdn3_rules('response_headers','Response headers',$p['response_headers']);
    echo '<p class="text-sm">Exact paths take precedence over prefixes, then extension rules. Query-string ignoring and stale serving should only be enabled for content suitable for shared caching.</p></fieldset>';
    echo '<fieldset class="w-full rounded border p-4"><legend class="font-semibold">Traffic protection</legend><div class="grid gap-3 sm:grid-cols-3">';
    cdn3_field('request_rate','Requests per second per IP (0 unlimited)',$p['request_rate'],'number'); cdn3_field('burst','Extra burst requests',$p['burst'],'number'); cdn3_field('connections','Concurrent connections per IP (0 unlimited)',$p['connections'],'number');
    cdn3_field('signed_url_env','Signed download key reference (CDN_SIGNING_…)',$p['signed_url_env']);
    echo '</div><p class="my-2 text-sm">A signing-key reference protects downloads with expiring links. Configure the secret in the website server environment; its value is never displayed here.</p>';
    foreach (['ip_allow'=>'Allowed IPs/CIDRs (empty allows all)','ip_deny'=>'Blocked IPs/CIDRs (checked first)'] as $name=>$label) echo '<label class="my-2 block text-sm">'.cdn_h($label).'<textarea class="block w-full rounded border p-2" name="'.cdn_h($name).'">'.cdn_h(implode("\n",$p[$name])).'</textarea></label>';
    echo '</fieldset>';
}
function cdn3_deployment_view(mysqli $db,array $nodes): void {
    echo '<h2 class="mt-8 text-lg font-semibold">Configuration deployments</h2><p class="my-2 text-sm">Domain edits remain drafts. Create a snapshot, review its changes, deploy to one canary, then promote after activation and external checks pass.</p>';
    cdn_form('draft'); cdn_input('title','Deployment title'); cdn_button('Create configuration draft'); echo '</form>';
    foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_deployments ORDER BY id DESC LIMIT 30') as $d) {
        echo '<section class="my-3 rounded border p-4"><h3 class="font-semibold">#'.cdn_h($d['id']).' · '.cdn_h($d['title']).' · '.cdn_h($d['status']).'</h3><p class="text-sm">'.cdn_h($d['created_at']).' UTC · '.cdn_h($d['actor']).'</p>';
        $snapshots=es_cdn2_rows($db,'SELECT * FROM cdn_bash_snapshots WHERE deployment_id=? ORDER BY node_id',[$d['id']]);
        echo '<details><summary>Review changes by host</summary>';
        foreach ($snapshots as $snapshot) {
            $before=es_cdn3_redact(es_cdn3_decode($snapshot['previous_json'])); $after=es_cdn3_redact(es_cdn3_decode($snapshot['desired_json']));
            echo '<h4 class="my-2 font-semibold">'.cdn_h($snapshot['node_id']).'</h4><div class="grid gap-3 md:grid-cols-2"><div><p>Previously published</p><pre class="max-h-80 overflow-auto text-xs">'.cdn_h(json_encode($before,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)).'</pre></div><div><p>Proposed configuration</p><pre class="max-h-80 overflow-auto text-xs">'.cdn_h(json_encode($after,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)).'</pre></div></div>';
        }
        echo '</details>';
        if ($d['status']==='draft') {
            cdn_form('deploy'); echo '<input type="hidden" name="deployment_id" value="'.cdn_h($d['id']).'"><input type="hidden" name="deploy_action" value="canary"><select class="rounded border p-2" name="canary_node">';
            foreach ($snapshots as $snapshot) echo '<option value="'.cdn_h($snapshot['node_id']).'">'.cdn_h($snapshot['node_id']).'</option>';
            echo '</select>'; cdn_button('Deploy to canary'); echo '</form>';
        }
        if ($d['status']==='canary') {
            cdn_form('deploy'); echo '<input type="hidden" name="deployment_id" value="'.cdn_h($d['id']).'"><input type="hidden" name="deploy_action" value="promote">'; cdn_button('Promote to remaining hosts'); echo '</form>';
        }
        if (in_array($d['status'],['canary','published'],true)) {
            cdn_form('deploy'); echo '<input type="hidden" name="deployment_id" value="'.cdn_h($d['id']).'"><input type="hidden" name="deploy_action" value="rollback">'; cdn_button('Roll back this deployment'); echo '</form>';
        }
        echo '</section>';
    }
}
function cdn3_monitor_view(mysqli $db): void {
    echo '<h2 class="mt-8 text-lg font-semibold">Alerts and external checks</h2>';
    $alerts=es_cdn2_rows($db,'SELECT * FROM cdn_bash_alerts WHERE resolved_at IS NULL ORDER BY severity,opened_at DESC LIMIT 100');
    foreach ($alerts as $a) {
        echo '<div class="my-2 rounded border p-3"><strong>'.cdn_h($a['severity']).'</strong> · '.cdn_h($a['node_id']).' · '.cdn_h($a['message']);
        if ($a['acknowledged_at']) echo ' · Acknowledged';
        else { cdn_form('ack'); echo '<input type="hidden" name="fingerprint" value="'.cdn_h($a['fingerprint']).'">'; cdn_button('Acknowledge'); echo '</form>'; }
        echo '</div>';
    }
    echo '<details class="my-3"><summary>Latest external availability checks</summary>';
    foreach (es_cdn2_rows($db,'SELECT * FROM cdn_bash_probes ORDER BY checked_at DESC LIMIT 100') as $p) echo '<p class="text-sm">'.cdn_h($p['hostname']).' · '.cdn_h($p['node_id']).' · HTTP '.cdn_h($p['status_code']).' · '.cdn_h(round((float)$p['latency_ms'],1)).' ms · '.cdn_h($p['checked_at']).' UTC · Consecutive failures '.cdn_h($p['failures']).'</p>';
    echo '</details><h3 class="mt-5 font-semibold">Hourly traffic history · last 24 hours</h3><p class="text-sm">Access-log windows reported by hosts. Best-effort operational counters; gaps may occur during outages or log rotation.</p><div class="overflow-x-auto"><table class="w-full text-sm"><tr><th>Hour (UTC)</th><th>Requests</th><th>Bytes delivered</th><th>Cache hit %</th><th>5xx</th><th>Mean origin latency (ms)</th></tr>';
    foreach (es_cdn2_rows($db,'SELECT DATE_FORMAT(received_at,"%Y-%m-%d %H:00") AS hour,SUM(requests) AS requests,SUM(bytes) AS bytes,SUM(hits) AS hits,SUM(errors) AS errors,AVG(origin_latency_ms) AS latency FROM cdn_bash_metric_history WHERE received_at>UTC_TIMESTAMP()-INTERVAL 24 HOUR GROUP BY hour ORDER BY hour DESC') as $h) {
        echo '<tr><td>'.cdn_h($h['hour']).'</td><td>'.cdn_h($h['requests']).'</td><td>'.cdn_h($h['bytes']).'</td><td>'.cdn_h($h['requests'] ? round(100*$h['hits']/$h['requests'],1) : 0).'</td><td>'.cdn_h($h['errors']).'</td><td>'.cdn_h(round((float)$h['latency'],1)).'</td></tr>';
    }
    echo '</table></div><p class="text-xs">Origin latency is the mean of reported interval means; it is not a percentile. History retention: seven days.</p>';
}
?>
<script>
function cdnRemoveRule(button) {
  const row=button.closest('[data-rule-row]');
  if(row.parentElement.children.length>1)row.remove();
  else row.querySelectorAll('input').forEach(e=>e.value='');
}
function cdnAddRule(kind) {
  const list=document.querySelector('[data-rule-list="'+kind+'"]');
  const template=list.querySelector('[data-rule-row]');
  if(!template)return;
  const row=template.cloneNode(true);
  const existing=Array.from(list.querySelectorAll('[name]')).map(e=>Number((e.name.match(/\[(\d+)\]/)||[])[1]||0));
  const next=Math.max(-1,...existing)+1;
  row.querySelectorAll('[name]').forEach(e=>{e.name=e.name.replace(/\[\d+\]/,'['+next+']');if(e.tagName==='INPUT')e.value='';});
  list.appendChild(row);
}
</script>
