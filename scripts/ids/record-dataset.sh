#!/usr/bin/env bash
# Records the IDS training set in the lab (ids/data/lab-windows.csv).
#
# Five benchmark initiating hosts (user "bench") run ordinary, benign workloads at
# different intensities against the protected portal, each in its own SDP session, while
# the IDS records every telemetry window it receives from two accepting hosts
# (IDS_RECORD_PATH, enforcement off). Workloads:
#
#   class 0  application-paced usage: browsing with think times, API polling (up to ~20
#            requests/s), downloads of a 256 KiB file (sdp-client load)
#   class 1  excessive, machine-paced volume: closed-loop load tests with the standard
#            `hey` tool through the session's local forwarder (1 to 25 concurrent
#            workers, rate-limited and unlimited, small pages and downloads)
#
# The windows are then labelled with the class of the workload that produced them
# (python -m sdp_ids.dataset label). Rebuild the IDS image afterwards to train on it:
#   docker compose build ids && docker compose up -d --wait ids
#
# Usage: ./scripts/ids/record-dataset.sh [--duration SECONDS] [--reps N]
set -euo pipefail
cd "$(dirname "$0")/../.."

DUR=40
REPS=2
while [ $# -gt 0 ]; do
    case "$1" in
        --duration) DUR="$2"; shift 2 ;;
        --reps) REPS="$2"; shift 2 ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RAW="/data/raw-$STAMP.csv"
WORK="results/dataset-$STAMP"
mkdir -p "$WORK"
MANIFEST="$WORK/manifest.csv"
echo "session_id,profile,label,start,end" > "$MANIFEST"

ex() { docker compose exec -T "$@"; }
export SDP_MODE=proposed COMPOSE_PROFILES=proposed,bench

echo "[record] starting the lab: 2 accepting hosts, IDS recording to $RAW (no enforcement)"
IDS_ENFORCE=0 IDS_RECORD_PATH="$RAW" docker compose up -d --build --wait --scale gateway=2
for _ in $(seq 1 30); do
    n="$(ex controller sdp-controller status -json | grep -o '"public_addr"' | wc -l)"
    [ "$n" -ge 2 ] && break
    sleep 1
done

# run IH PROFILE LABEL KIND ARGS...
#   KIND=load: ARGS are sdp-client load flags
#   KIND=hey:  ARGS are hey flags (URL path appended)
run() {
    local ih="$1" profile="$2" label="$3" kind="$4"
    shift 4
    ex "$ih" sdp-client connect portal >/dev/null 2>&1 || { echo "[record] $ih: connect failed"; return 0; }
    local sid start end
    sid="$(ex "$ih" jq -r .session.session_id /tmp/sdp-session.json)"
    start="$(date +%s.%N)"
    if [ "$kind" = load ]; then
        ex "$ih" sdp-client load --duration "${DUR}s" "$@" >/dev/null
    else
        local path="$1" out
        shift
        ex "$ih" pkill -f 'sdp-client proxy' >/dev/null 2>&1 || true
        sleep 0.2
        ex -d "$ih" sh -c "exec sdp-client proxy --listen 127.0.0.1:8080 > /tmp/proxy.log 2>&1"
        sleep 0.5
        out="$(ex "$ih" hey -z "${DUR}s" "$@" "http://127.0.0.1:8080$path")"
        ex "$ih" pkill -f 'sdp-client proxy' >/dev/null 2>&1 || true
        if ! grep -qE '^\s+\[200\]' <<<"$out"; then
            echo "[record] $ih $profile: no successful response, not recorded"
            ex "$ih" sdp-client disconnect >/dev/null 2>&1 || true
            return 0
        fi
    fi
    end="$(date +%s.%N)"
    ex "$ih" sdp-client disconnect >/dev/null 2>&1 || true
    echo "$sid,$profile,$label,$start,$end" >> "$MANIFEST"
    echo "[record] $ih $profile (class $label) done"
}

F=/portal/files/report.bin
host1() {
    run ih-bench-1 browse-slow 0 load --think 2s
    run ih-bench-1 poll-10 0 load --think 100ms
    run ih-bench-1 hey-c1 1 hey /portal/ -c 1
    run ih-bench-1 download 0 load --think 1s --path "$F"
}
host2() {
    run ih-bench-2 browse 0 load --think 500ms
    run ih-bench-2 poll-20 0 load --think 50ms
    run ih-bench-2 hey-c5 1 hey /portal/ -c 5
    run ih-bench-2 poll-5 0 load --think 200ms
}
host3() {
    run ih-bench-3 browse-multi 0 load --think 1s --workers 3
    run ih-bench-3 poll-10x2 0 load --think 100ms --workers 2
    run ih-bench-3 hey-c10 1 hey /portal/ -c 10
    run ih-bench-3 download-fast 0 load --think 250ms --path "$F"
}
host4() {
    run ih-bench-4 hey-c25 1 hey /portal/ -c 25
    run ih-bench-4 browse 0 load --think 500ms
    run ih-bench-4 hey-q100 1 hey /portal/ -c 5 -q 20
    run ih-bench-4 poll-10 0 load --think 100ms
}
host5() {
    run ih-bench-5 hey-download 1 hey "$F" -c 4
    run ih-bench-5 browse-slow 0 load --think 2s
    run ih-bench-5 poll-5 0 load --think 200ms
    run ih-bench-5 hey-c2 1 hey /portal/ -c 2
}

for rep in $(seq 1 "$REPS"); do
    echo "[record] repetition $rep/$REPS (about $((4 * (DUR + 5)))s)"
    host1 & host2 & host3 & host4 & host5 &
    wait
done
sleep 3 # last telemetry windows

docker compose cp "$MANIFEST" ids:/data/manifest-"$STAMP".csv
ex ids python -m sdp_ids.dataset label --raw "$RAW" --manifest /data/manifest-"$STAMP".csv \
    --out /data/lab-windows-"$STAMP".csv
docker compose cp ids:"$RAW" "$WORK/raw.csv"
docker compose cp ids:/data/lab-windows-"$STAMP".csv ids/data/lab-windows.csv
echo "[record] ids/data/lab-windows.csv: $(($(wc -l < ids/data/lab-windows.csv) - 1)) labelled windows (raw recording in $WORK)"

echo "[record] restoring the IDS (enforcement on, no recording)"
docker compose up -d --wait --scale gateway=1
