<?php
/** Real MySQL integration tests; use a disposable database, never the production database. */
require __DIR__.'/../integration/ericservices/includes/cdn-bash.php';
function verify(bool $ok,string $label): void { if (!$ok) throw new RuntimeException($label); }
$db = new mysqli(getenv('TEST_DB_HOST') ?: '127.0.0.1',getenv('TEST_DB_USER') ?: 'root',getenv('TEST_DB_PASSWORD') ?: '',getenv('TEST_DB_NAME') ?: 'cdn_test',(int)(getenv('TEST_DB_PORT') ?: 3306));
$schema=file_get_contents(__DIR__.'/../integration/ericservices/sql/migrations/20261102_cdn_bash_nodes.sql')."\n".file_get_contents(__DIR__.'/../integration/ericservices/sql/migrations/20261103_cdn_delivery_deployments.sql');
$db->multi_query($schema);
do { if ($result=$db->store_result()) $result->free(); } while ($db->more_results() && $db->next_result());
putenv('CDN_ENROLLMENT_KEY='.str_repeat('test-key',8));
$_SERVER['REMOTE_ADDR']='8.8.8.8';
$grant=bin2hex(random_bytes(32));
es_cdn2_db($db,'INSERT INTO cdn_bash_enrollments(token_hash,expected_ipv4,location,expires_at,created_by) VALUES (?,"8.8.8.8","test",UTC_TIMESTAMP()+INTERVAL 1 HOUR,"test")',[hash('sha256',$grant)]);
$body=['schema_version'=>1,'name'=>'test-edge','enrollment_id'=>'test_enrollment_'.bin2hex(random_bytes(10)),'agent'=>'ericcdn-bash'];
$identity=es_cdn2_register($db,$grant,$body);
verify(es_cdn2_register($db,$grant,$body)===$identity,'Enrollment retry created another identity');
$node=es_cdn2_auth($db,$identity['node_id'],$identity['node_token']);
verify($node['status']==='pending','Node did not require approval');
verify(es_cdn2_desired($db,$node)['domains']===[],'Pending node received assignments');
$denied=false;
try { es_cdn2_register($db,$grant,array_merge($body,['enrollment_id'=>'different_enrollment_id'])); } catch (RuntimeException $e) { $denied=$e->getCode()===409; }
verify($denied,'Enrollment grant reused for another identity');
es_cdn2_db($db,'UPDATE cdn_bash_nodes SET status="approved" WHERE id=?',[$node['id']]);
es_cdn2_db($db,'INSERT INTO cdn_bash_zones(name,provider_zone_id,token_env) VALUES (?,?,?)',['z'.bin2hex(random_bytes(4)).'.example.com',str_repeat('a',32),'CDN_CF_TEST']);
$zone=$db->insert_id;
$host='cdn.'.bin2hex(random_bytes(4)).'.example.com';
es_cdn2_db($db,'INSERT INTO cdn_bash_domains(cdn_uid,zone_id,hostname,origin,cache_ttl) VALUES (1,?,?,"origin.example.com",60)',[$zone,$host]);
$domain=$db->insert_id;
es_cdn2_db($db,'INSERT INTO cdn_bash_assignments(node_id,domain_id) VALUES (?,?)',[$node['id'],$domain]);
$node=es_cdn2_auth($db,$node['id'],$identity['node_token']);
$state=es_cdn2_compile($db,$node);
verify(count($state['domains'])===1 && $state['domains'][0]['managed_tls']===true,'Assigned domain not delivered');
es_cdn2_db($db,'UPDATE cdn_bash_domains SET cache_version=cache_version+1 WHERE id=?',[$domain]);
$newState=es_cdn2_compile($db,$node);
verify($state['revision']!==$newState['revision'] && $newState['domains'][0]['cache_version']==='v2','Cache invalidation failed');
es_cdn2_db($db,'UPDATE cdn_bash_assignments SET draining=1,drain_until=NULL WHERE node_id=?',[$node['id']]);
verify(count(es_cdn2_compile($db,$node)['domains'])===1,'Domain retired before DNS drain');
es_cdn2_db($db,'UPDATE cdn_bash_assignments SET drain_until=UTC_TIMESTAMP()-INTERVAL 1 SECOND WHERE node_id=?',[$node['id']]);
verify(es_cdn2_compile($db,$node)['domains']===[],'Expired drain did not retire domain');
// Authoring changes are not visible to hosts until a staged deployment publishes them.
es_cdn2_db($db,'UPDATE cdn_bash_assignments SET draining=0,drain_until=NULL WHERE node_id=?',[$node['id']]);
es_cdn2_db($db,'UPDATE cdn_bash_nodes SET agent_version=3 WHERE id=?',[$node['id']]);
$node=es_cdn2_auth($db,$node['id'],$identity['node_token']);
verify(es_cdn2_desired($db,$node)['domains']===[],'An unpublished edit reached the host');
$draft=es_cdn3_draft($db,'Test canary','test');
es_cdn3_deploy($db,$draft,'canary','test',$node['id']);
$node=es_cdn2_auth($db,$node['id'],$identity['node_token']);
$live=es_cdn2_desired($db,$node);
verify(count($live['domains'])===1,'Canary did not publish its snapshot');
$denied=false;
try { es_cdn3_deploy($db,$draft,'promote','test'); } catch(RuntimeException $e) { $denied=true; }
verify($denied,'Promoted before the canary reported health');
$report=['schema_version'=>1,'status'=>'applied','applied_revision'=>$live['revision'],'metrics'=>['agent_version'=>3,'interval_seconds'=>60,'nginx_up'=>true,'disk_free_bytes'=>2000000000,'disk_total_bytes'=>10000000000,'domains'=>[]]];
es_cdn3_report($db,$node,$report);
es_cdn2_db($db,'UPDATE cdn_bash_nodes SET last_seen_at=UTC_TIMESTAMP(),report_json=? WHERE id=?',[json_encode($report),$node['id']]);
es_cdn2_db($db,'INSERT INTO cdn_bash_probes(node_id,hostname,checked_at,status_code,revision,latency_ms,failures) VALUES (?,?,UTC_TIMESTAMP(),200,?,5,0)',[$node['id'],$host,$live['revision']]);
es_cdn3_deploy($db,$draft,'promote','test');
es_cdn2_db($db,'UPDATE cdn_bash_domains SET cache_version=cache_version+1 WHERE id=?',[$domain]);
$draft2=es_cdn3_draft($db,'Second revision','test');
es_cdn3_deploy($db,$draft2,'canary','test',$node['id']);
es_cdn3_deploy($db,$draft2,'rollback','test');
$node=es_cdn2_auth($db,$node['id'],$identity['node_token']);
verify(es_cdn2_desired($db,$node)['revision']===$live['revision'],'Rollback did not restore the previous configuration');
verify((int)$node['deployment_id']===$draft,'Rollback lost the earlier deployment identity');
es_cdn3_deploy($db,$draft,'rollback','test');
$node=es_cdn2_auth($db,$node['id'],$identity['node_token']);
verify(es_cdn2_desired($db,$node)['domains']===[],'Chained rollback did not restore the baseline');
$bad=false;
try { es_cdn2_auth($db,'other-node',$identity['node_token']); } catch (RuntimeException $e) { $bad=$e->getCode()===401; }
verify($bad,'Credential accepted for another node');
es_cdn2_db($db,'UPDATE cdn_bash_nodes SET status="revoked",token_hash=NULL WHERE id=?',[$node['id']]);
$bad=false;
try { es_cdn2_auth($db,$node['id'],$identity['node_token']); } catch (RuntimeException $e) { $bad=true; }
verify($bad,'Revoked credential accepted');
echo "PASS: MySQL enrollment retry/approval, authorization, assignments, purge, drain, canary gates, chained rollback and revocation.\n";
