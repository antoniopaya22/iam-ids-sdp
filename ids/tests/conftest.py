import csv
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sdp_ids.dataset import LABELLED_COLUMNS  # noqa: E402
from sdp_ids.features import FEATURE_NAMES  # noqa: E402


def window_features(rate: float, rng: np.random.Generator, conns: int = 1) -> dict:
    """A plausible sdp-window-v1 feature dict for a session sending `rate` requests/s.

    Test fixture only: the lab model is trained on windows recorded in the lab
    (ids/data/lab-windows.csv), not on this generator.
    """
    r = max(rate * rng.uniform(0.85, 1.15), 0.0)
    return {
        "req_rate": r,
        "bytes_in_rate": r * rng.uniform(300, 400),
        "bytes_out_rate": r * rng.uniform(500, 700),
        "err_ratio": 0.0,
        "mean_latency_ms": rng.uniform(1, 3) + (4 if rate > 100 else 0),
        "new_conn_rate": rng.uniform(0, 0.5),
        "open_conns": float(conns),
        "stalled_conns": 0.0,
        "mean_iat_ms": 1000.0 / max(r, 0.5),
        "iat_cv": rng.uniform(0.1, 0.5) if rate < 50 else rng.uniform(0.6, 1.5),
        "distinct_paths": float(rng.integers(1, 4)),
    }


def window(session="s1", user="alice", rate=1.0, rng=None, conns=1):
    rng = rng or np.random.default_rng(0)
    return {"session_id": session, "username": user, "subject": f"sub-{user}", "client_ip": "10.233.0.40",
            "gateway": "gw-1", "window_start": "2026-01-01T00:00:00Z", "window_secs": 2.0,
            "features": window_features(rate, rng, conns)}


@pytest.fixture
def rng():
    return np.random.default_rng(42)


@pytest.fixture
def labelled_csv(tmp_path, rng):
    path = tmp_path / "windows.csv"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=LABELLED_COLUMNS)
        w.writeheader()
        for profile, rate, label, conns in [("browse", 0.5, 0, 1), ("browse", 2, 0, 1), ("poll", 10, 0, 1),
                                            ("poll", 20, 0, 1), ("load-c1", 300, 1, 1), ("load-c10", 1500, 1, 10)]:
            for _ in range(40):
                f_ = window_features(rate, rng, conns)
                w.writerow({"profile": profile, "label": label, "gateway": "gw-1", "window_secs": 2.0,
                            **{k: f_[k] for k in FEATURE_NAMES}})
    return str(path)
