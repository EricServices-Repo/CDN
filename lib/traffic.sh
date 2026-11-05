#!/usr/bin/env bash
# shellcheck disable=SC2154 # work is provided by the installed entrypoint.
traffic_window() {
    local inode=none size=0 offset=0 previous=0 now complete next_offset interval backlog=0
    now=$(date +%s)
    : > "$work/traffic.tsv"
    if [[ -f $ACCESS_LOG ]]; then
        inode=$(stat -c %i "$ACCESS_LOG"); size=$(stat -c %s "$ACCESS_LOG")
        if [[ -f $STATE/log-cursor.json ]]; then
            previous=$(jq -r '.time // 0' "$STATE/log-cursor.json")
            if [[ $(jq -r .inode "$STATE/log-cursor.json") == "$inode" ]]; then offset=$(jq -r '.offset // 0' "$STATE/log-cursor.json"); fi
        fi
        [[ $offset =~ ^[0-9]+$ && $offset -le $size ]] || offset=0
        dd if="$ACCESS_LOG" of="$work/traffic.raw" iflag=skip_bytes,count_bytes skip="$offset" count=16777216 status=none
        complete=$(tail -c 1 "$work/traffic.raw" | od -An -tu1 | tr -d '[:space:]')
        if [[ -z $complete || $complete == 10 ]]; then cp "$work/traffic.raw" "$work/traffic.tsv";
        else sed '$d' "$work/traffic.raw" > "$work/traffic.tsv"; fi
        next_offset=$((offset+$(wc -c < "$work/traffic.tsv")))
        backlog=$((size-next_offset))
    else next_offset=0; fi
    [[ $previous =~ ^[0-9]+$ && $previous -gt 0 ]] || previous=$((now-60))
    interval=$((now-previous)); ((interval>0)) || interval=1
    jq -n --arg inode "$inode" --argjson offset "$next_offset" --argjson time "$now" '{inode:$inode,offset:$offset,time:$time}' > "$work/cursor.json"
    atomic_install "$work/cursor.json" "$STATE/log-cursor.json"
    jq -n --argjson seconds "$interval" --argjson backlog "$backlog" '{seconds:$seconds,backlog_bytes:$backlog}' > "$work/window.json"
}
traffic_domain() {
    local host=$1 seconds=$2
    awk -F '\t' -v host="$host" -v seconds="$seconds" '
      {matchhost=($1==host)}
      matchhost && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
        n++; b+=$3; if($4=="HIT")h++; if($4=="MISS")m++; if($2>=500)e++;
        parts=split($6,times,","); latency=0; observed=0;
        for(i=1;i<=parts;i++){gsub(/ /,"",times[i]);if(times[i]~/^[0-9.]+$/){latency+=times[i];observed=1}}
        if(observed){us+=latency; un++}
      }
      END {printf "{\"requests\":%.0f,\"bytes\":%.0f,\"cache_hits\":%.0f,\"cache_misses\":%.0f,\"errors_5xx\":%.0f,\"bandwidth_bps\":%.3f,\"origin_latency_ms\":%.3f}",n,b,h,m,e,(b*8/seconds),(un ? us*1000/un : 0)}' "$work/traffic.tsv"
}
