<?php
// Compatibility URL for imported identities. Import existing nodes before enabling this wrapper.
$id=$_GET['node_id'] ?? ''; $operation=$_GET['operation'] ?? '';
if (!is_string($id) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/D',$id) || !in_array($operation,['desired','report'],true)) { http_response_code(400); exit; }
$cdnLegacyTransport=true;
$_GET['route']='nodes/'.$id.'/'.$operation;
require __DIR__.'/index.php';
