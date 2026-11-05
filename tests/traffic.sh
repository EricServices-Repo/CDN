#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/lib/node.sh"; source "$ROOT/lib/runtime.sh"; source "$ROOT/lib/traffic.sh"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
work="$TMP/work"; STATE="$TMP/state"; ACCESS_LOG="$TMP/access.log"
mkdir "$work" "$STATE"
printf 'cdn.example.test\t200\t100\tHIT\t0.020\t-\ncdn.example.test\t200\t200\tMISS\t0.055\t0.040\ncdn.example.test\t503\t30\tMISS\t0.100\t0.050, 0.020\nother.test\t200\t999\tHIT\t0.010\t-\n' > "$work/traffic.tsv"
traffic_domain cdn.example.test 60 | jq -e '.requests==3 and .bytes==330 and .cache_hits==1 and .cache_misses==2 and .errors_5xx==1 and .bandwidth_bps==44 and .origin_latency_ms==55' >/dev/null
printf '*.example.test\t200\t50\tHIT\t0.01\t-\n' >> "$work/traffic.tsv"
traffic_domain '*.example.test' 60 | jq -e '.requests==1 and .bytes==50' >/dev/null
if [[ $(uname -s) == Linux ]]; then
    cp "$work/traffic.tsv" "$ACCESS_LOG"
    printf 'cdn.example.test\t200\t' >> "$ACCESS_LOG"
    traffic_window
    [[ $(wc -l < "$work/traffic.tsv") -eq 5 ]]
    printf '123\tMISS\t0.1\t0.1\n' >> "$ACCESS_LOG"
    traffic_window
    [[ $(wc -l < "$work/traffic.tsv") -eq 1 ]]
    traffic_domain cdn.example.test 60 | jq -e '.requests==1 and .bytes==123' >/dev/null
    traffic_window
    [[ ! -s $work/traffic.tsv ]]
    mv "$ACCESS_LOG" "$TMP/rotated.log"
    printf 'cdn.example.test\t200\t50\tHIT\t0.01\t-\n' > "$ACCESS_LOG"
    traffic_window
    traffic_domain cdn.example.test 60 | jq -e '.requests==1 and .bytes==50' >/dev/null
fi
printf 'PASS: incremental traffic aggregation, wildcard attribution, bandwidth and origin latency (cursor/rotation checks run on Linux).\n'
