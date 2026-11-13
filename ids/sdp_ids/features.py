"""Telemetry feature set exported by the accepting hosts.

Keep FEATURE_NAMES in sync with internal/gateway/features.go (feature set "sdp-window-v1").
Every value summarises one SDP session on one accepting host during one window
(2 s by default).
"""

from __future__ import annotations

import math

import numpy as np

FEATURE_SET = "sdp-window-v1"

FEATURE_NAMES = [
    "req_rate",         # requests per second
    "bytes_in_rate",    # request bytes per second (headers + body, approximate)
    "bytes_out_rate",   # response body bytes per second
    "err_ratio",        # share of responses with status >= 400
    "mean_latency_ms",  # mean time to serve a request at the AH
    "new_conn_rate",    # TCP/TLS connections opened per second
    "open_conns",       # connections open at the end of the window
    "stalled_conns",    # open connections without a complete request after a threshold
    "mean_iat_ms",      # mean inter-arrival time between requests
    "iat_cv",           # coefficient of variation of inter-arrival times
    "distinct_paths",   # number of distinct URL paths requested
]

# Ratios stay linear; every other feature is non-negative and heavy-tailed, so it is
# compressed with log1p before reaching the classifiers ("log1p-v1" transform).
_LINEAR = {"err_ratio", "iat_cv"}
TRANSFORM = "log1p-v1"


def _value(features: dict, name: str) -> float:
    v = features.get(name, 0.0)
    try:
        v = float(v)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(v) or math.isinf(v) or v < 0:
        return 0.0
    return v


def vectorize(features: dict) -> np.ndarray:
    """Turn one window's feature dict into the model input vector."""
    out = np.empty(len(FEATURE_NAMES), dtype=float)
    for i, name in enumerate(FEATURE_NAMES):
        v = _value(features, name)
        out[i] = v if name in _LINEAR else math.log1p(v)
    return out


def vectorize_many(rows) -> np.ndarray:
    return np.vstack([vectorize(r) for r in rows]) if rows else np.empty((0, len(FEATURE_NAMES)))
