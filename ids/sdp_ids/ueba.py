"""Per-identity behavioural baseline (the UEBA part of the IDS).

The IAM tells the accepting host who is behind every SDP session, so the IDS can keep a
baseline per identity (Keycloak user) instead of per IP address. For each identity and
each monitored feature it keeps an exponentially weighted mean and variance in log space,
starting from a population prior learnt from the normal windows of the training data.

A window *deviates* when, for at least one monitored feature, it is both

* far above the identity's baseline (z-score >= ``z_threshold``), and
* several times larger in absolute terms (ratio >= ``min_ratio``),

so a user who usually sends 1 request/s and suddenly sends hundreds is flagged, while
the normal jitter of a light user is not. Only increases are considered: the baseline
answers "is this identity consuming far more than usual?". Windows that are flagged (by
the baseline or by the classifiers) are not learnt, so a burst cannot become the new normal.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field

DEFAULT_FEATURES = ("req_rate", "bytes_out_rate")


@dataclass
class _Stat:
    mean: float
    var: float
    n: float


@dataclass
class Deviation:
    deviates: bool
    feature: str = ""
    value: float = 0.0
    baseline: float = 0.0
    z: float = 0.0
    ratio: float = 0.0
    details: dict = field(default_factory=dict)


class UEBA:
    def __init__(self, prior: dict, features=DEFAULT_FEATURES, prior_n: float = 10.0,
                 max_n: float = 60.0, z_threshold: float = 4.0, min_ratio: float = 5.0,
                 sigma_floor: float = 0.25):
        """prior maps feature -> (mean, var) of log1p(feature) over normal windows."""
        self.features = tuple(features)
        self.prior = {f: (float(prior[f][0]), max(float(prior[f][1]), sigma_floor ** 2)) for f in self.features}
        self.prior_n = prior_n
        self.max_n = max_n
        self.z_threshold = z_threshold
        self.min_ratio = min_ratio
        self.sigma_floor = sigma_floor
        self._stats: dict[str, dict[str, _Stat]] = {}
        self._windows: dict[str, int] = {}
        self._lock = threading.Lock()

    def _get(self, identity: str) -> dict[str, _Stat]:
        st = self._stats.get(identity)
        if st is None:
            st = {f: _Stat(mean=m, var=v, n=self.prior_n) for f, (m, v) in self.prior.items()}
            self._stats[identity] = st
            self._windows[identity] = 0
        return st

    def score(self, identity: str, features: dict) -> Deviation:
        with self._lock:
            st = self._get(identity)
            worst = Deviation(deviates=False)
            details = {}
            for f in self.features:
                raw = max(float(features.get(f, 0.0) or 0.0), 0.0)
                x = math.log1p(raw)
                s = st[f]
                sigma = max(math.sqrt(s.var), self.sigma_floor)
                z = (x - s.mean) / sigma
                base = math.expm1(s.mean)
                ratio = raw / max(base, 1e-3)
                details[f] = {"value": raw, "baseline": base, "z": round(z, 2), "ratio": round(ratio, 2)}
                flagged = z >= self.z_threshold and ratio >= self.min_ratio
                if flagged and (not worst.deviates or z > worst.z):
                    worst = Deviation(True, f, raw, base, z, ratio)
                elif not worst.deviates and z > worst.z:
                    worst = Deviation(False, f, raw, base, z, ratio)
            worst.details = details
            return worst

    def update(self, identity: str, features: dict) -> None:
        with self._lock:
            st = self._get(identity)
            for f in self.features:
                x = math.log1p(max(float(features.get(f, 0.0) or 0.0), 0.0))
                s = st[f]
                s.n = min(s.n + 1.0, self.max_n)
                d = x - s.mean
                s.mean += d / s.n
                s.var = (1.0 - 1.0 / s.n) * (s.var + d * d / s.n)
            self._windows[identity] += 1

    def snapshot(self) -> dict:
        with self._lock:
            return {
                ident: {
                    "windows_learnt": self._windows.get(ident, 0),
                    **{f: {"typical": round(math.expm1(s.mean), 3),
                           "log_sigma": round(math.sqrt(s.var), 3)} for f, s in st.items()},
                }
                for ident, st in self._stats.items()
            }
