<?php
if (PHP_SAPI!=='cli') { http_response_code(404); exit; }
require_once __DIR__.'/../config.php';
require_once __DIR__.'/../includes/cdn-bash.php';
$errors = es_cdn2_reconcile($con);
es_cdn3_monitor($con);
foreach ($errors as $error) fwrite(STDERR,$error.PHP_EOL);
exit($errors ? 1 : 0);
