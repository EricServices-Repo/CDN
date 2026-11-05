<?php
/** Freeze existing configurations before enabling explicit draft publication. */
if (PHP_SAPI!=='cli') { http_response_code(404); exit; }
require_once __DIR__.'/../config.php';
require_once __DIR__.'/../includes/cdn-bash.php';
$apply=in_array('--apply',$argv,true);
foreach (es_cdn2_rows($con,'SELECT * FROM cdn_bash_nodes WHERE published_state IS NULL') as $node) {
    $state=es_cdn2_compile($con,$node);
    echo ($apply ? 'Baseline ' : 'Would baseline ').$node['id'].' with '.count($state['domains'])." domains\n";
    if ($apply) es_cdn2_db($con,'UPDATE cdn_bash_nodes SET published_state=? WHERE id=? AND published_state IS NULL',[es_cdn3_encode($state),$node['id']]);
}

if ($apply) es_cdn2_db($con,'UPDATE cdn_bash_settings SET value="1" WHERE name="deployment_ready"');
