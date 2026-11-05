<?php
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
function cdn_reply(array $body, int $code=200): never {
    http_response_code($code);
    echo json_encode($body,JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? '')!=='POST') cdn_reply(['error'=>'POST required'],405);
if (strtolower(explode(';',$_SERVER['CONTENT_TYPE'] ?? '')[0])!=='application/json') cdn_reply(['error'=>'JSON required'],415);
$raw = file_get_contents('php://input',false,null,0,1048577);
if ($raw===false || strlen($raw)>1048576) cdn_reply(['error'=>'Request too large'],413);
try {
    $body = json_decode($raw,true,32,JSON_THROW_ON_ERROR);
    if (!is_array($body)) throw new InvalidArgumentException('JSON object required.');
    require_once __DIR__.'/../../../config.php';
    require_once __DIR__.'/../../../includes/cdn-bash.php';
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer ([A-Za-z0-9_-]{32,256})$/D',$auth,$match)) cdn_reply(['error'=>'Bearer token required'],401);
    $token = $match[1];
    if (!es_cdn3_ready($con)) cdn_reply(['error'=>'Apply the delivery migration and baseline configurations before enabling this API'],503);
    $route = $_GET['route'] ?? '';
    es_cdn2_rate($con,'ip:'.($_SERVER['REMOTE_ADDR'] ?? ''),120);
    if ($route==='nodes/register') {
        es_cdn2_rate($con,'enroll:'.($_SERVER['REMOTE_ADDR'] ?? ''),10);
        cdn_reply(es_cdn2_register($con,$token,$body));
    }
    if (!is_string($route) || !preg_match('#^nodes/([A-Za-z0-9_-]{1,64})/(desired|report|dns/(?:add|remove))$#D',$route,$parts)) cdn_reply(['error'=>'Unknown route'],404);
    $node = es_cdn2_auth($con,$parts[1],$token);
    if (($cdnLegacyTransport ?? false) && $parts[2]==='report' && !isset($body['metrics'])) $body['metrics']=['agent_version'=>1,'interval_seconds'=>60,'domains'=>[],'nginx_up'=>null];
    es_cdn2_rate($con,'node:'.$node['id'],90);
    if ($parts[2]==='desired') cdn_reply(es_cdn2_desired($con,$node));
    if ($parts[2]==='report') {
        if (($body['schema_version'] ?? null)!==1 || !preg_match('/^[A-Za-z0-9_-]{1,64}$/D',$body['applied_revision'] ?? '') ||
            !in_array($body['status'] ?? '',['applied','error','rolled_back'],true) || !is_array($body['metrics'] ?? null)) throw new InvalidArgumentException('Invalid health report.');
        // Only our renderer consumes this JSON; all strings are escaped at output.
        $con->begin_transaction();
        try {
        es_cdn3_report($con,$node,$body);
        es_cdn2_db($con,'UPDATE cdn_bash_nodes SET last_seen_at=UTC_TIMESTAMP(),report_json=? WHERE id=?',[json_encode($body,JSON_THROW_ON_ERROR),$node['id']]);
        $con->commit();
        } catch (Throwable $e) { $con->rollback(); throw $e; }
        cdn_reply(['ok'=>true]);
    }
    cdn_reply(es_cdn2_challenge($con,$node,basename($parts[2]),$body));
} catch (JsonException|InvalidArgumentException $e) {
    cdn_reply(['error'=>'Invalid request: '.$e->getMessage()],400);
} catch (Throwable $e) {
    $code = in_array($e->getCode(),[401,403,409,429,503],true) ? $e->getCode() : 503;
    // Never expose database/provider credentials or SQL text.
    error_log('CDN Bash API failure: '.get_class($e));
    cdn_reply(['error'=>$code===503 ? 'CDN service temporarily unavailable' : 'Request denied'],$code);
}
