"""Model files: what the IDS loads at start-up.

Format ``sdp-ids-model/v1`` is a joblib file holding a dict::

    {"format": "sdp-ids-model/v1", "feature_set": "sdp-window-v1", "transform": "log1p-v1",
     "scaler": StandardScaler | None, "model": <estimator with predict_proba>,
     "ueba_prior": {feature: [mean, var]}, "meta": {...}}

A *bare* estimator (for example an ``ApollonMAB`` trained and pickled with the Apollon
repository) is accepted too: it must have been fitted on ``features.vectorize`` output (the
11 sdp-window-v1 features after log1p) and expose ``predict_proba``. Pickles that refer to
Apollon's module path ``MAB.apollon_mab`` are mapped to the vendored copy in this package.
"""

from __future__ import annotations

import pickle
import sys
from dataclasses import dataclass, field

import joblib
import numpy as np

from . import apollon_mab
from .features import FEATURE_SET, TRANSFORM

FORMAT = "sdp-ids-model/v1"


def _alias_apollon_modules() -> None:
    """Let pickles created with the Apollon repository (MAB.apollon_mab) load here."""
    if "MAB.apollon_mab" not in sys.modules:
        import types
        pkg = sys.modules.setdefault("MAB", types.ModuleType("MAB"))
        pkg.apollon_mab = apollon_mab  # type: ignore[attr-defined]
        sys.modules["MAB.apollon_mab"] = apollon_mab


@dataclass
class LoadedModel:
    estimator: object
    scaler: object | None = None
    ueba_prior: dict | None = None
    meta: dict = field(default_factory=dict)

    def predict(self, X: np.ndarray):
        """Return (probability of class 1, arm name) for every row."""
        X = np.asarray(X, dtype=float)
        if self.scaler is not None:
            X = self.scaler.transform(X)
        est = self.estimator
        if hasattr(est, "predict_proba_with_arms"):
            proba, _clusters, arms = est.predict_proba_with_arms(X)
            names = est.arm_names() if hasattr(est, "arm_names") else [str(i) for i in range(int(arms.max()) + 1)]
            return proba[:, 1], [names[int(a)] for a in arms]
        if hasattr(est, "select_arms"):  # Apollon repository class without the helper
            proba, _clusters, arms = est._route(X, "predict_proba")
            names = [type(a).__name__ for a in getattr(est, "arms", [])]
            return proba[:, 1], [names[int(a)] if names else str(int(a)) for a in arms]
        proba = est.predict_proba(X)
        return proba[:, 1], [type(est).__name__] * len(X)

    @property
    def arms(self):
        est = self.estimator
        if hasattr(est, "arm_names"):
            return est.arm_names()
        return [type(a).__name__ for a in getattr(est, "arms", [est])]


def save(path: str, estimator, scaler, ueba_prior: dict, meta: dict) -> None:
    joblib.dump({"format": FORMAT, "feature_set": FEATURE_SET, "transform": TRANSFORM,
                 "scaler": scaler, "model": estimator, "ueba_prior": ueba_prior, "meta": meta}, path)


def load(path: str) -> LoadedModel:
    _alias_apollon_modules()
    try:
        obj = joblib.load(path)
    except Exception:  # plain pickle written by the Apollon repository
        with open(path, "rb") as f:
            obj = pickle.load(f)  # noqa: S301 - model files are trusted lab artefacts
    if isinstance(obj, dict) and obj.get("format") == FORMAT:
        if obj.get("feature_set") != FEATURE_SET or obj.get("transform") != TRANSFORM:
            raise ValueError(f"model expects {obj.get('feature_set')}/{obj.get('transform')}, "
                             f"this IDS provides {FEATURE_SET}/{TRANSFORM}")
        return LoadedModel(obj["model"], obj.get("scaler"), obj.get("ueba_prior"), obj.get("meta", {}))
    if hasattr(obj, "predict_proba"):
        return LoadedModel(obj, None, None, {"source": "bare estimator", "path": path})
    raise ValueError(f"{path}: not an {FORMAT} file nor an estimator with predict_proba")
