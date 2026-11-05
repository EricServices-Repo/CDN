<?php
/** Constrained CDN delivery policies. Stored rules contain secret references, not secrets. */
function es_cdn3_int(mixed $value,int $min,int $max): int {
    if (!is_int($value) || $value<$min || $value>$max) throw new InvalidArgumentException('Numeric delivery setting is out of range.');
    return $value;
}
function es_cdn3_path(mixed $path): bool {
    return is_string($path) && strlen($path)<=1024 && preg_match('#^/[A-Za-z0-9/_.~-]*$#D',$path)===1;
}
function es_cdn3_cidr(mixed $value): bool {
    if (!is_string($value) || substr_count($value,'/')>1) return false;
    $parts=explode('/',$value); $ip=$parts[0];
    if (!filter_var($ip,FILTER_VALIDATE_IP)) return false;
    return !isset($parts[1]) || (ctype_digit($parts[1]) && strlen($parts[1])<=3 && (int)$parts[1]<=(str_contains($ip,':') ? 128 : 32));
}
function es_cdn3_policy(array $input,bool $resolveSecret=false): array {
    $p=array_replace(['backup_origins'=>[],'connect_timeout'=>5,'read_timeout'=>60,'serve_stale'=>false,
      'query_string'=>'include','cache_rules'=>[],'redirects'=>[],'response_headers'=>[],
      'cors_origin'=>'','download'=>'','request_rate'=>0,'burst'=>0,'connections'=>0,
      'ip_allow'=>[],'ip_deny'=>[],'signed_url_env'=>''],$input);
    $allowed=['backup_origins','connect_timeout','read_timeout','serve_stale','query_string','cache_rules','redirects','response_headers','cors_origin','download','request_rate','burst','connections','ip_allow','ip_deny','signed_url_env'];
    if (array_diff(array_keys($p),$allowed)) throw new InvalidArgumentException('Unsupported delivery setting.');
    foreach (['backup_origins'=>3,'cache_rules'=>30,'redirects'=>30,'response_headers'=>20,'ip_allow'=>100,'ip_deny'=>100] as $field=>$limit) {
        if (!is_array($p[$field]) || !array_is_list($p[$field]) || count($p[$field])>$limit) throw new InvalidArgumentException('Too many or invalid delivery rules.');
    }
    foreach (['connect_timeout'=>[1,60],'read_timeout'=>[1,600],'request_rate'=>[0,10000],'burst'=>[0,10000],'connections'=>[0,10000]] as $field=>$bounds) es_cdn3_int($p[$field],...$bounds);
    if (!is_bool($p['serve_stale']) || !in_array($p['query_string'],['include','ignore'],true) || !in_array($p['download'],['','inline','attachment'],true)) throw new InvalidArgumentException('Invalid delivery option.');
    foreach ($p['backup_origins'] as $origin) if (!is_string($origin) || !es_cdn2_host($origin)) throw new InvalidArgumentException('Backup origins must be HTTPS hostnames.');
    foreach (array_merge($p['ip_allow'],$p['ip_deny']) as $cidr) if (!es_cdn3_cidr($cidr)) throw new InvalidArgumentException('Invalid IP address or CIDR.');
    if (!is_string($p['cors_origin']) || !preg_match('#^(?:|\*|https://[a-z0-9.-]+(?::[0-9]{1,5})?)$#D',$p['cors_origin'])) throw new InvalidArgumentException('CORS must be empty, *, or an HTTPS origin.');
    $matches=[]; $exact=[];
    foreach ($p['cache_rules'] as $rule) {
        if (!is_array($rule) || !in_array($rule['match'] ?? '',['exact','prefix','extension'],true) || !isset($rule['value'],$rule['ttl'])) throw new InvalidArgumentException('Invalid cache rule.');
        if ($rule['match']==='extension' ? (!is_string($rule['value']) || !preg_match('/^[a-z0-9]{1,16}$/D',$rule['value'])) : (!es_cdn3_path($rule['value']) || $rule['value']==='/' || $rule['value']==='/_ericcdn_health')) throw new InvalidArgumentException('Invalid cache rule path or extension.');
        es_cdn3_int($rule['ttl'],0,604800);
        $key=$rule['match'].':'.$rule['value'];
        if (isset($matches[$key])) throw new InvalidArgumentException('Duplicate cache rule.');
        $matches[$key]=true;
        if ($rule['match']==='exact') $exact[]=$rule['value'];
    }
    $redirects=[];
    foreach ($p['redirects'] as $r) {
        if (!is_array($r) || !es_cdn3_path($r['path'] ?? null) || $r['path']==='/_ericcdn_health' || !is_string($r['target'] ?? null) ||
            !preg_match('#^(https://[a-z0-9.-]+)?/[A-Za-z0-9/_.~?=&%+@\#:-]*$#D',$r['target']) || str_starts_with($r['target'],'//') ||
            !in_array($r['code'] ?? 0,[301,302,307,308],true) || isset($redirects[$r['path']]) || in_array($r['path'],$exact,true)) throw new InvalidArgumentException('Invalid, conflicting or duplicate redirect.');
        $redirects[$r['path']]=true;
    }
    foreach ($p['response_headers'] as $header) {
        if (!is_array($header) || !in_array($header['name'] ?? '',['X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Content-Security-Policy','Access-Control-Expose-Headers','X-Robots-Tag'],true) ||
            !is_string($header['value'] ?? null) || strlen($header['value'])>2048 || preg_match('/[\x00-\x1f\x7f]/',$header['value'])) throw new InvalidArgumentException('Invalid response header.');
    }
    if (!is_string($p['signed_url_env']) || ($p['signed_url_env']!=='' && !preg_match('/^CDN_SIGNING_[A-Z0-9_]{1,80}$/D',$p['signed_url_env']))) throw new InvalidArgumentException('Use a CDN_SIGNING_… server secret reference.');
    if ($resolveSecret) {
        $key=$p['signed_url_env']==='' ? '' : getenv($p['signed_url_env']);
        if (!is_string($key) || ($key!=='' && !preg_match('/^[A-Za-z0-9_-]{32,128}$/D',$key)) || ($p['signed_url_env']!=='' && $key==='')) throw new RuntimeException('Signing key is not configured correctly.');
        unset($p['signed_url_env']); $p['signing_key']=$key;
    }
    return $p;
}
function es_cdn3_lines(mixed $text): array {
    if (!is_string($text)) throw new InvalidArgumentException('Text field required.');
    return array_values(array_filter(array_map('trim',preg_split('/\R/',$text)),fn($line)=>$line!==''));
}
function es_cdn3_policy_post(array $post): array {
    $p=[];
    foreach (['connect_timeout'=>5,'read_timeout'=>60,'request_rate'=>0,'burst'=>0,'connections'=>0] as $field=>$default) {
        $raw=$post[$field] ?? $default;
        if (filter_var($raw,FILTER_VALIDATE_INT)===false) throw new InvalidArgumentException('Integer required for '.$field);
        $p[$field]=(int)$raw;
    }
    foreach (['query_string'=>'include','cors_origin'=>'','download'=>'','signed_url_env'=>''] as $field=>$default) $p[$field]=trim((string)($post[$field] ?? $default));
    $p['serve_stale']=isset($post['serve_stale']);
    foreach (['backup_origins','ip_allow','ip_deny'] as $field) $p[$field]=es_cdn3_lines($post[$field] ?? '');
    foreach (['cache_rules','redirects','response_headers'] as $field) {
        $rows=$post[$field] ?? [];
        if (!is_array($rows)) throw new InvalidArgumentException('Invalid rule fields.');
        $p[$field]=[];
        foreach ($rows as $row) {
            if (!is_array($row)) throw new InvalidArgumentException('Invalid rule.');
            $marker=$field==='cache_rules' ? 'value' : ($field==='redirects' ? 'path' : 'value');
            if (trim((string)($row[$marker] ?? ''))==='') continue;
            $p[$field][]=match($field) {
                'cache_rules'=>['match'=>(string)($row['match'] ?? ''),'value'=>trim((string)$row['value']),'ttl'=>es_cdn3_post_int($row['ttl'] ?? '')],
                'redirects'=>['path'=>trim((string)$row['path']),'target'=>trim((string)($row['target'] ?? '')),'code'=>es_cdn3_post_int($row['code'] ?? '')],
                default=>['name'=>(string)($row['name'] ?? ''),'value'=>(string)$row['value']]
            };
        }
    }
    return es_cdn3_policy($p);
}
function es_cdn3_post_int(mixed $value): int {
    if (filter_var($value,FILTER_VALIDATE_INT)===false) throw new InvalidArgumentException('Integer required.');
    return (int)$value;
}
function es_cdn3_state(array $domains): array {
    return ['schema_version'=>1,'revision'=>'r'.substr(hash('sha256',json_encode($domains,JSON_THROW_ON_ERROR|JSON_UNESCAPED_SLASHES)),0,32),'domains'=>$domains];
}
function es_cdn3_redact(array $state): array {
    foreach ($state['domains'] ?? [] as $i=>$domain) {
        if (!empty($domain['policy']['signing_key'])) $state['domains'][$i]['policy']['signing_key']='[configured]';
    }
    return $state;
}
function es_cdn3_sign(string $host,string $path,int $ttl,string $secret): string {
    if (!es_cdn2_host($host) || !es_cdn3_path($path) || $ttl<1 || $ttl>86400 || !preg_match('/^[A-Za-z0-9_-]{32,128}$/D',$secret)) throw new InvalidArgumentException('Invalid signed download request.');
    $expires=time()+$ttl;
    $hash=rtrim(strtr(base64_encode(md5($expires.$path.' '.$secret,true)),'+/','-_'),'=');
    return 'https://'.$host.$path.'?md5='.$hash.'&expires='.$expires;
}
