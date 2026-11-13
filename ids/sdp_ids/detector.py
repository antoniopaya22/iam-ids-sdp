"""Decision logic: classifier pool (Apollon MAB) + per-identity baseline (UEBA).

For every telemetry window of an SDP session:

1. the MAB picks one classifier by Thompson sampling and returns the probability that the
   window is *excessive* (class 1: saturating, machine-paced load) rather than
   application-paced usage (class 0);
2. the UEBA baseline of the identity says whether the window deviates from what that user
   usually does;
3. with policy ``both`` (default) a window is anomalous when both agree; with ``either`` when
   any of them fires. ``consecutive`` anomalous windows of the same session raise an alert.

Alerts are raised once per session; the controller then revokes the session.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass

import numpy as np

from .features import vectorize
from .model import LoadedModel
from .ueba import UEBA

# Used when no model provides a prior (record-only mode, tests).
FALLBACK_PRIOR = {"req_rate": (np.log1p(2.0), 1.0), "bytes_out_rate": (np.log1p(4000.0), 2.0)}


@dataclass
class Decision:
    session_id: str
    identity: str
    gateway: str
    window_start: str
    req_rate: float
    probability: float | None
    arm: str | None
    classifier_anomalous: bool | None
    ueba_deviates: bool
    ueba_feature: str
    ueba_z: float
    ueba_ratio: float
    ueba_baseline: float
    anomalous: bool
    streak: int
    alert: bool
    reason: str = ""


class Detector:
    def __init__(self, model: LoadedModel | None, ueba: UEBA | None = None, policy: str = "both",
                 consecutive: int = 2, threshold: float = 0.5):
        if policy not in ("both", "either", "classifier", "ueba"):
            raise ValueError(f"unknown policy {policy}")
        self.model = model
        prior = (model.ueba_prior if model and model.ueba_prior else None) or FALLBACK_PRIOR
        self.ueba = ueba or UEBA(prior)
        self.policy = policy
        self.consecutive = max(1, consecutive)
        self.threshold = threshold
        self._streak: dict[str, int] = {}
        self._alerted: dict[str, float] = {}
        self._lock = threading.Lock()
        self.recent = deque(maxlen=200)
        self.counters = {"windows": 0, "anomalous": 0, "alerts": 0}

    @staticmethod
    def identity_of(w: dict) -> str:
        return w.get("username") or w.get("subject") or f"ip:{w.get('client_ip', '?')}"

    def process(self, w: dict) -> Decision:
        feats = w.get("features", {})
        ident = self.identity_of(w)
        sid = w.get("session_id", "")
        p = arm = clf = None
        if self.model is not None:
            probs, arms = self.model.predict(vectorize(feats)[None, :])
            p, arm = float(probs[0]), arms[0]
            clf = p >= self.threshold
        dev = self.ueba.score(ident, feats)
        if self.policy == "both":
            anomalous = dev.deviates and (clf if clf is not None else True)
        elif self.policy == "either":
            anomalous = dev.deviates or bool(clf)
        elif self.policy == "classifier":
            anomalous = bool(clf)
        else:
            anomalous = dev.deviates
        if not anomalous and not dev.deviates and not clf:
            self.ueba.update(ident, feats)

        with self._lock:
            self.counters["windows"] += 1
            streak = self._streak.get(sid, 0) + 1 if anomalous else 0
            self._streak[sid] = streak
            alert = anomalous and streak >= self.consecutive and sid not in self._alerted
            if anomalous:
                self.counters["anomalous"] += 1
            if alert:
                self._alerted[sid] = time.time()
                self.counters["alerts"] += 1
        reason = ""
        if anomalous:
            parts = []
            if dev.deviates:
                parts.append(f"{dev.feature} {dev.value:.1f}/s is {dev.ratio:.0f}x the baseline of {ident} "
                             f"({dev.baseline:.1f}/s, z={dev.z:.1f})")
            if clf:
                parts.append(f"classifier {arm} (Thompson-sampled) p={p:.2f}")
            reason = "; ".join(parts) + f"; {streak} consecutive windows"
        d = Decision(session_id=sid, identity=ident, gateway=w.get("gateway", ""),
                     window_start=w.get("window_start", ""), req_rate=float(feats.get("req_rate", 0.0)),
                     probability=p, arm=arm, classifier_anomalous=clf, ueba_deviates=dev.deviates,
                     ueba_feature=dev.feature, ueba_z=round(dev.z, 2), ueba_ratio=round(dev.ratio, 2),
                     ueba_baseline=round(dev.baseline, 3), anomalous=anomalous, streak=streak, alert=alert,
                     reason=reason)
        self.recent.append(asdict(d))
        return d

    def forget_alert(self, session_id: str) -> None:
        """Allow a new alert for the session (e.g. the controller could not be reached)."""
        with self._lock:
            self._alerted.pop(session_id, None)
