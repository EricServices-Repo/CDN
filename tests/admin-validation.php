<?php
require __DIR__.'/../integration/ericservices/includes/cdn-bash.php';
function check(bool $condition,string $label): void { if (!$condition) throw new RuntimeException($label); }
foreach (['cdn.example.com','*.cdn.example.com'] as $host) check(es_cdn2_host($host,true),'valid host');
foreach (['evil.com; include /tmp/x;','bad..example.com','-bad.example.com','UPPER.example.com','foo.example.com/','*.*.example.com'] as $host) check(!es_cdn2_host($host,true),'invalid host accepted');
check(es_cdn2_in_zone('*.assets.example.com','example.com'),'wildcard zone');
check(!es_cdn2_in_zone('example.com.attacker.test','example.com'),'zone suffix confusion');
check(!es_cdn2_in_zone('notexample.com','example.com'),'zone boundary');
check(es_cdn2_matches('a.b.assets.example.com','*.assets.example.com'),'wildcard loop');
check(!es_cdn2_matches('assets.example.com','*.assets.example.com'),'apex wildcard');
foreach (['100.64.0.1','224.0.0.1','192.0.2.1','127.0.0.1','10.0.0.1','169.254.169.254','192.168.1.1','::1','fc00::1','::ffff:127.0.0.1','64:ff9b::7f00:1'] as $ip) check(!es_cdn2_public_ip($ip),'private address accepted: '.$ip);
check(es_cdn2_public_ip('8.8.8.8'),'public address');
echo "PASS: Admin domain, zone-boundary, origin-loop and IP validation.\n";
