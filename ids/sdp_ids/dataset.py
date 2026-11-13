"""Datasets of telemetry windows.

The IDS can record every window it receives (``IDS_RECORD_PATH``). Recordings are raw: one
row per window with the session id and the 11 features. ``label`` joins them with a manifest
(session id -> workload profile -> class) written by scripts/ids/record-dataset.sh, which
produces the training set used at image build time (ids/data/lab-windows.csv).

Classes:
  0  application-paced usage: a person browsing, an application polling an API, downloads
  1  excessive volume: saturating, machine-paced load from a standard load-testing tool
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import re
import sys

import numpy as np

from .features import FEATURE_NAMES

RAW_COLUMNS = ["time", "session_id", "username", "gateway", "window_secs"] + FEATURE_NAMES
LABELLED_COLUMNS = ["profile", "label", "gateway", "window_secs"] + FEATURE_NAMES


def read_labelled(paths) -> tuple[list[dict], np.ndarray, list[str]]:
    rows: list[dict] = []
    for p in paths:
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                rows.append(r)
    feats = [{k: float(r[k]) for k in FEATURE_NAMES} for r in rows]
    y = np.array([int(r["label"]) for r in rows], dtype=int)
    profiles = [r.get("profile", "") for r in rows]
    return feats, y, profiles


def parse_time(s: str) -> float:
    """Seconds since the epoch of an RFC 3339 timestamp (Go prints up to 9 fraction digits)."""
    s = s.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)(\.\d+)?(.*)$", s)
    if m and m.group(2):
        s = m.group(1) + m.group(2)[:7] + m.group(3)
    return dt.datetime.fromisoformat(s).timestamp()


def label(raw_path: str, manifest_path: str, out_path: str, min_requests: float = 0.0) -> int:
    """Join a raw recording with a manifest (session_id, profile, label[, start, end]).

    With start/end (epoch seconds of the workload), only windows that lie entirely inside
    the workload are kept, so the set-up and tear-down of each session are not labelled
    with the workload's class.
    """
    with open(manifest_path, newline="") as f:
        manifest = {r["session_id"]: r for r in csv.DictReader(f)}
    n = 0
    with open(raw_path, newline="") as fin, open(out_path, "w", newline="") as fout:
        w = csv.DictWriter(fout, fieldnames=LABELLED_COLUMNS)
        w.writeheader()
        for r in csv.DictReader(fin):
            m = manifest.get(r["session_id"])
            if m is None:
                continue
            secs = float(r["window_secs"])
            if m.get("start") and m.get("end"):
                t0 = parse_time(r["time"])
                if t0 < float(m["start"]) or t0 + secs > float(m["end"]):
                    continue
            # Windows where the session was idle carry no behaviour: skip them.
            if float(r["req_rate"]) * secs <= min_requests:
                continue
            w.writerow({"profile": m["profile"], "label": m["label"], "gateway": r["gateway"],
                        "window_secs": r["window_secs"], **{k: r[k] for k in FEATURE_NAMES}})
            n += 1
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m sdp_ids.dataset")
    sub = ap.add_subparsers(dest="cmd", required=True)
    lb = sub.add_parser("label", help="join a raw recording with a session manifest")
    lb.add_argument("--raw", required=True)
    lb.add_argument("--manifest", required=True)
    lb.add_argument("--out", required=True)
    lb.add_argument("--min-requests", type=float, default=0.0)
    args = ap.parse_args(argv)
    n = label(args.raw, args.manifest, args.out, args.min_requests)
    print(f"{n} labelled windows -> {args.out}")
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
