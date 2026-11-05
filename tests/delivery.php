<?php
require __DIR__.'/../integration/ericservices/includes/cdn-bash.php';
function insist(bool $ok,string $message): void { if (!$ok) throw new RuntimeException($message); }
$state=json_decode(file_get_contents(__DIR__.'/fixtures/delivery-state.json'),true,64,JSON_THROW_ON_ERROR);
$p=$state['domains'][0]['policy']; $secret=$p['signing_key']; unset($p['signing_key']);
$p['signed_url_env']='CDN_SIGNING_TEST'; putenv('CDN_SIGNING_TEST='.$secret); putenv('CDN_ENROLLMENT_KEY='.str_repeat('test-secret',4));
$compiled=es_cdn3_policy($p,true);
insist($compiled['signing_key']===$secret,'Signing key was not resolved');
$state['domains'][0]['policy']=$compiled;
$encoded=es_cdn3_encode($state);
insist(!str_contains($encoded,$secret),'Plaintext signing key leaked into a snapshot');
insist(es_cdn3_decode($encoded)===$state,'Encrypted snapshot did not round-trip');
$redacted=es_cdn3_redact($state);
insist(!str_contains(json_encode($redacted),$secret),'Preview leaked signing key');
$link=es_cdn3_sign('cdn.example.test','/asset.css',60,$secret);
parse_str(parse_url($link,PHP_URL_QUERY),$args);
$expected=rtrim(strtr(base64_encode(md5($args['expires'].'/asset.css '.$secret,true)),'+/','-_'),'=');
insist(hash_equals($expected,$args['md5']),'Signed-link format does not match nginx');
foreach ([['request_rate'=>-1],['ip_allow'=>['127.0.0.1; return 200;']],['response_headers'=>[['name'=>'Set-Cookie','value'=>'private=1']]],['redirects'=>[['path'=>'/x','target'=>'//evil.test','code'=>302]]],['signed_url_env'=>'OTHER_ENV']] as $change) {
    $denied=false;
    try { es_cdn3_policy(array_replace($p,$change)); } catch (InvalidArgumentException $e) { $denied=true; }
    insist($denied,'Invalid delivery policy accepted');
}
// Tampering must fail authentication, not produce a new valid configuration.
$bad=substr($encoded,0,-6).'AAAAAA'; $denied=false;
try { es_cdn3_decode($bad); } catch (Throwable $e) { $denied=true; }
insist($denied,'Tampered snapshot accepted');
echo "PASS: Admin delivery policy, encrypted snapshots, secret redaction, signed URLs and tamper rejection.\n";
$denied=false;
try { es_cdn3_probe(['public_ipv4'=>'127.0.0.1'],['hostname'=>'cdn.example.test'],'r1'); } catch(RuntimeException $e) { $denied=true; }
insist($denied,'External monitor accepted a loopback probe target');
