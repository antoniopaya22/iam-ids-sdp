#!/usr/bin/env python3
"""Turn the JSON printed by `sdp-client bench` into CSV files (standard library only).

    summarize.py [--quiet] OUT MODE TOPOLOGY IHS AHS   append runs.csv and load.csv rows
    summarize.py --report OUT                          write summary.csv and print it

All values are local measurements of this lab; they are not the paper's numbers.
"""

import csv
import glob
import json
import os
import statistics
import sys

PHASES = ["token", "controller_spa", "controller", "gateway_spa", "first_request"]
RUN_COLS = (["mode", "topology", "ihs", "ahs", "ih", "run", "gateways_ok"]
            + [f"{p}_ms" for p in PHASES] + ["setup_ms"]
            + [f"{p}_bytes" for p in PHASES] + ["setup_bytes"])
LOAD_COLS = ["mode", "topology", "ihs", "ahs", "ih", "ok", "failed", "seconds", "requests_per_sec",
             "requests_per_10min", "mean_latency_ms", "p95_latency_ms", "setup_errors"]
SUMMARY_COLS = ["mode", "topology", "ihs", "ahs", "setups", "setup_ms_mean", "setup_ms_sd",
                "setup_ms_median", "setup_kb_mean", "token_ms_mean", "controller_ms_mean",
                "throughput_per_ih_10min_mean", "requests_failed", "setup_errors"]


def append(path, cols, rows):
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        if new:
            w.writeheader()
        w.writerows(rows)


def collect(out, mode, topo, ihs, ahs, quiet):
    runs, loads = [], []
    for path in sorted(glob.glob(os.path.join(out, "raw", f"{mode}-t{topo}-ih*.json"))):
        ih = path.rsplit("-ih", 1)[1].split(".")[0]
        try:
            with open(path) as f:
                rep = json.load(f)
        except (OSError, ValueError) as e:
            print(f"  {path}: unreadable ({e})", file=sys.stderr)
            continue
        for i, r in enumerate(rep.get("runs") or [], 1):
            t, b = r["timings"], r["bytes"]
            row = {"mode": mode, "topology": topo, "ihs": ihs, "ahs": ahs, "ih": ih, "run": i,
                   "gateways_ok": sum(1 for s in (r.get("status") or {}).values() if s == 200),
                   "setup_ms": t["total_ms"], "setup_bytes": b["total"]}
            for p in PHASES:
                row[f"{p}_ms"] = t.get(f"{p}_ms", 0)
                row[f"{p}_bytes"] = b.get(p, 0)
            runs.append(row)
        ld = rep.get("load") or {}
        loads.append({"mode": mode, "topology": topo, "ihs": ihs, "ahs": ahs, "ih": ih,
                      "ok": ld.get("ok", 0), "failed": ld.get("failed", 0), "seconds": round(ld.get("seconds", 0), 2),
                      "requests_per_sec": round(ld.get("requests_per_sec", 0), 2),
                      "requests_per_10min": round(ld.get("requests_per_10min", 0)),
                      "mean_latency_ms": round(ld.get("mean_latency_ms", 0), 2),
                      "p95_latency_ms": round(ld.get("p95_latency_ms", 0), 2),
                      "setup_errors": len(rep.get("errors") or [])})
    append(os.path.join(out, "runs.csv"), RUN_COLS, runs)
    append(os.path.join(out, "load.csv"), LOAD_COLS, loads)
    if runs:
        setup = [r["setup_ms"] for r in runs]
        kb = statistics.mean(r["setup_bytes"] for r in runs) / 1024
        thr = statistics.mean(x["requests_per_10min"] for x in loads) if loads else 0
        print(f"  {len(runs)} set-ups: {statistics.mean(setup):.1f} ms mean, {kb:.1f} KB; "
              f"throughput {thr:.0f} requests/10 min per IH")
    else:
        print("  no successful set-up", file=sys.stderr)
    return 0 if runs else 1


def report(out):
    with open(os.path.join(out, "runs.csv")) as f:
        runs = list(csv.DictReader(f))
    with open(os.path.join(out, "load.csv")) as f:
        loads = list(csv.DictReader(f))
    keys = []
    for r in runs + loads:
        k = (r["mode"], r["topology"], r["ihs"], r["ahs"])
        if k not in keys:
            keys.append(k)
    rows = []
    for k in keys:
        rs = [r for r in runs if (r["mode"], r["topology"], r["ihs"], r["ahs"]) == k]
        ls = [x for x in loads if (x["mode"], x["topology"], x["ihs"], x["ahs"]) == k]
        setup = [float(r["setup_ms"]) for r in rs]

        def mean(col, src=rs):
            vals = [float(r[col]) for r in src]
            return round(statistics.mean(vals), 1) if vals else ""

        rows.append({
            "mode": k[0], "topology": k[1], "ihs": k[2], "ahs": k[3], "setups": len(rs),
            "setup_ms_mean": mean("setup_ms"),
            "setup_ms_sd": round(statistics.stdev(setup), 1) if len(setup) > 1 else "",
            "setup_ms_median": round(statistics.median(setup), 1) if setup else "",
            "setup_kb_mean": round(statistics.mean(float(r["setup_bytes"]) for r in rs) / 1024, 2) if rs else "",
            "token_ms_mean": mean("token_ms"), "controller_ms_mean": mean("controller_ms"),
            "throughput_per_ih_10min_mean": round(statistics.mean(float(x["requests_per_10min"]) for x in ls)) if ls else "",
            "requests_failed": sum(int(x["failed"]) for x in ls),
            "setup_errors": sum(int(x["setup_errors"]) for x in ls),
        })
    with open(os.path.join(out, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_COLS)
        w.writeheader()
        w.writerows(rows)
    print("Local measurements (this machine):")
    print(f"{'mode':<12} {'topo':>4} {'IH':>3} {'AH':>3} {'set-up ms':>10} {'sd':>6} {'set-up KB':>9} "
          f"{'req/10 min per IH':>18} {'failed':>7}")
    for r in rows:
        print(f"{r['mode']:<12} {r['topology']:>4} {r['ihs']:>3} {r['ahs']:>3} {r['setup_ms_mean']:>10} "
              f"{r['setup_ms_sd']:>6} {r['setup_kb_mean']:>9} {r['throughput_per_ih_10min_mean']:>18} "
              f"{r['requests_failed']:>7}")
    return 0


def main(argv):
    quiet = "--quiet" in argv
    argv = [a for a in argv if a != "--quiet"]
    if argv and argv[0] == "--report":
        return report(argv[1])
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    return collect(*argv, quiet=quiet)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
