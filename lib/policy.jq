def integer($lo;$hi): type=="number" and floor==. and .>=$lo and .<=$hi;
def path: type=="string" and test("^/[A-Za-z0-9/_.~-]*$") and length<=1024;
def text: type=="string" and length<=2048 and (test("[\\x00-\\x1f\\x7f]")|not);
def policy:
  type=="object" and
  ((.backup_origins // []) | type=="array" and length<=3 and all(.[]; type=="string")) and
  ((.connect_timeout // 5) | integer(1;60)) and ((.read_timeout // 60) | integer(1;600)) and
  ((.serve_stale // false) | type=="boolean") and
  ((.query_string // "include") | .=="include" or .=="ignore") and
  ((.cors_origin // "") | type=="string" and ( .=="" or .=="*" or test("^https://[a-z0-9.-]+(:[0-9]{1,5})?$"))) and
  ((.download // "") | .=="" or .=="inline" or .=="attachment") and
  ((.request_rate // 0)|integer(0;10000)) and ((.burst // 0)|integer(0;10000)) and
  ((.connections // 0)|integer(0;10000)) and
  ((.signing_key // "") | type=="string" and (.=="" or test("^[A-Za-z0-9_-]{32,128}$"))) and
  ((.ip_allow // []) | type=="array" and length<=100 and all(.[];type=="string")) and
  ((.ip_deny // []) | type=="array" and length<=100 and all(.[];type=="string")) and
  ((.cache_rules // []) | type=="array" and length<=30 and
    all(.[]; (.match=="prefix" or .match=="exact" or .match=="extension") and
      (if .match=="extension" then (.value|type=="string" and test("^[a-z0-9]{1,16}$")) else (.value|path and .!="/") end) and
      (.ttl|integer(0;604800))) and
    ([.[]|.match+":"+.value]|length==(unique|length))) and
  ((.redirects // []) | type=="array" and length<=30 and all(.[];
    (.path|path and .!="/_ericcdn_health") and
    (.target|text and test("^(https://[a-z0-9.-]+)?/[A-Za-z0-9/_.~?=&%+@#:-]*$") and (startswith("//")|not)) and
    (.code==301 or .code==302 or .code==307 or .code==308)) and
    ([.[].path]|length==(unique|length))) and
  ((.response_headers // []) | type=="array" and length<=20 and all(.[];
    (.name|IN("X-Content-Type-Options","X-Frame-Options","Referrer-Policy","Content-Security-Policy","Access-Control-Expose-Headers","X-Robots-Tag")) and (.value|text)));
all(.domains[]; (.policy // {} | policy) and
  (([ (.policy.cache_rules // [])[] | select(.match=="exact") | .value ] -
    [ (.policy.redirects // [])[] | .path ]) | length) ==
  ([ (.policy.cache_rules // [])[] | select(.match=="exact") | .value ] | length))
