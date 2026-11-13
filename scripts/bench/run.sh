#!/usr/bin/env bash
# Local benchmark: traditional vs proposed SDP on the four topologies of the paper (Sect. 6.1).
#
#   topology 1: 1 IH, 1 controller,  1 AH        topology 3: 1 IH, 1 controller,  5 AHs
#   topology 2: 1 IH, 1 controller,  2 AHs       topology 4: 5 IHs, 1 controller, 10 AHs
#
# For every mode and topology, each initiating host (ih-bench-N, user "bench") measures
# RUNS connection set-ups (IAM login in proposed mode, SPA + mTLS to the controller, SPA
# to every AH, first request) and then runs a closed-loop workload (1 worker, 100 ms think
# time, requests spread over all the AHs) for DURATION seconds. Throughput is reported in
# requests per 10 minutes, extrapolated from DURATION.
#
# Results are LOCAL MEASUREMENTS on this machine, written as CSV to results/bench-<time>/
# (git-ignored). They are not the paper's numbers.
#
# Usage: ./scripts/bench/run.sh [--quick] [--modes traditional,proposed] [--topologies 1,2,3,4]
#                               [--runs N] [--duration SECONDS] [--think DURATION]
#   --quick: 3 set-ups and a 10 s workload per IH (default: 10 set-ups, 60 s)
set -euo pipefail
cd "$(dirname "$0")/../.."

MODES="traditional,proposed"
TOPOLOGIES="1,2,3,4"
RUNS=10
DURATION=60
THINK=100ms
PAUSE=5.5s # > the controller's SPA door (5 s): every set-up starts with the controller dark
while [ $# -gt 0 ]; do
    case "$1" in
        --quick) RUNS=3; DURATION=10; shift ;;
        --modes) MODES="$2"; shift 2 ;;
        --topologies) TOPOLOGIES="$2"; shift 2 ;;
        --runs) RUNS="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --think) THINK="$2"; shift 2 ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done

[ -f .env ] || { echo "run ./scripts/gen-env.sh first"; exit 1; }
OUT="results/bench-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT/raw"

topology() { # -> "IHS AHS"
    case "$1" in
        1) echo "1 1" ;; 2) echo "1 2" ;; 3) echo "1 5" ;; 4) echo "5 10" ;;
        *) echo "unknown topology $1" >&2; exit 2 ;;
    esac
}

{
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git_commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //')"
    echo "cpus: $(nproc)"
    echo "memory: $(grep MemTotal /proc/meminfo | awk '{print $2 " kB"}')"
    echo "kernel: $(uname -r)"
    echo "docker: $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
    echo "runs: $RUNS  workload: ${DURATION}s, 1 worker, think $THINK  pause between set-ups: $PAUSE"
} > "$OUT/environment.txt"
cat "$OUT/environment.txt"

ex() { docker compose exec -T "$@"; }
all_down() { COMPOSE_PROFILES=proposed,bench docker compose down --remove-orphans >/dev/null 2>&1 || true; }

IFS=, read -r -a modes <<<"$MODES"
IFS=, read -r -a topos <<<"$TOPOLOGIES"
built=0
for mode in "${modes[@]}"; do
    export SDP_MODE="$mode"
    if [ "$mode" = proposed ]; then export COMPOSE_PROFILES=proposed,bench; else export COMPOSE_PROFILES=bench; fi
    echo
    echo "=== mode $mode ==="
    all_down
    for t in "${topos[@]}"; do
        read -r ihs ahs <<<"$(topology "$t")"
        echo "--- topology $t: $ihs IH(s), 1 controller, $ahs AH(s)"
        build=""
        [ $built -eq 0 ] && build="--build" && built=1
        docker compose up -d $build --wait --scale gateway="$ahs" >/dev/null
        n=0
        for _ in $(seq 1 60); do
            n="$(ex controller sdp-controller status -json | grep -o '"public_addr"' | wc -l)"
            [ "$n" -eq "$ahs" ] && break
            sleep 1
        done
        [ "$n" -eq "$ahs" ] || { echo "controller sees $n gateways, expected $ahs"; exit 1; }
        for k in $(seq 1 "$ihs"); do
            ex "ih-bench-$k" sdp-client bench portal --runs "$RUNS" --pause "$PAUSE" \
                --duration "${DURATION}s" --think "$THINK" \
                > "$OUT/raw/$mode-t$t-ih$k.json" &
        done
        wait
        python3 scripts/bench/summarize.py --quiet "$OUT" "$mode" "$t" "$ihs" "$ahs"
    done
done
all_down

echo
python3 scripts/bench/summarize.py --report "$OUT"
echo
echo "CSV files in $OUT (local measurements on this machine, not the paper's numbers)."
echo "Restart the lab with: docker compose up -d --wait"
