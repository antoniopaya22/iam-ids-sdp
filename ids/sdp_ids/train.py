"""Train the lab model: ``python -m sdp_ids.train --data data/lab-windows.csv --out model.joblib``.

Fits a StandardScaler and an Apollon MAB (K-Means clusters x classifier pool, Beta
posteriors initialised on a validation split) on labelled telemetry windows, reports
hold-out metrics, and stores the population prior of the UEBA baseline (normal windows).
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import sys

import numpy as np
import sklearn
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from . import model as model_io
from .apollon_mab import ApollonMAB
from .dataset import read_labelled
from .features import FEATURE_SET, TRANSFORM, vectorize_many
from .ueba import DEFAULT_FEATURES


def fit(X: np.ndarray, y: np.ndarray, seed: int):
    scaler = StandardScaler().fit(X)
    mab = ApollonMAB(n_clusters=2, random_state=seed).fit(scaler.transform(X), y)
    return scaler, mab


def ueba_prior(feats: list[dict], y: np.ndarray) -> dict:
    prior = {}
    for f in DEFAULT_FEATURES:
        vals = np.array([math.log1p(max(r[f], 0.0)) for r, lab in zip(feats, y) if lab == 0])
        prior[f] = [float(vals.mean()), float(vals.var())] if len(vals) else [0.0, 1.0]
    return prior


def train(paths, out: str, seed: int = 7, test_size: float = 0.25) -> dict:
    feats, y, profiles = read_labelled(paths)
    if len(set(y.tolist())) != 2:
        raise SystemExit("training data needs both classes (0 and 1)")
    X = vectorize_many(feats)

    # Hold-out evaluation.
    idx = np.arange(len(y))
    tr, te = train_test_split(idx, test_size=test_size, random_state=seed, stratify=y)
    scaler, mab = fit(X[tr], y[tr], seed)
    Xte = scaler.transform(X[te])
    y_pred, arms = mab.predict(Xte, return_arms=True)
    tn, fp, fn, tp = confusion_matrix(y[te], y_pred, labels=[0, 1]).ravel()
    per_arm = {}
    for a, name in enumerate(mab.arm_names()):
        # Each arm answering alone (cluster-specific models), for comparison with the MAB.
        cl = mab.kmeans_.predict(Xte)
        pa = np.array([mab.models_[c][a].predict(Xte[i:i + 1])[0] for i, c in enumerate(cl)])
        per_arm[name] = round(float((pa == y[te]).mean()), 4)
    holdout = {
        "rows": int(len(te)), "accuracy": round(float((y_pred == y[te]).mean()), 4),
        "true_positive_rate": round(float(tp / max(tp + fn, 1)), 4),
        "false_positive_rate": round(float(fp / max(fp + tn, 1)), 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "per_arm_accuracy": per_arm,
        "arm_selection_share": {n: round(float(s), 3) for n, s in
                                zip(mab.arm_names(), np.bincount(arms, minlength=mab.n_arms) / len(arms))},
    }

    # Final model on all the data.
    scaler, mab = fit(X, y, seed)
    digests = {}
    for p in paths:
        with open(p, "rb") as f:
            digests[p] = hashlib.sha256(f.read()).hexdigest()
    meta = {
        "trained_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "feature_set": FEATURE_SET, "transform": TRANSFORM, "seed": seed,
        "data": digests, "rows": int(len(y)),
        "rows_per_class": {str(k): int(v) for k, v in sorted(collections.Counter(y.tolist()).items())},
        "rows_per_profile": dict(sorted(collections.Counter(profiles).items())),
        "arms": mab.arm_names(), "clusters": mab.n_clusters,
        "holdout": holdout, "scikit_learn": sklearn.__version__,
        "classes": {"0": "application-paced usage", "1": "excessive, machine-paced volume"},
    }
    model_io.save(out, mab, scaler, ueba_prior(feats, y), meta)
    return meta


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m sdp_ids.train")
    ap.add_argument("--data", nargs="+", required=True, help="labelled CSV file(s)")
    ap.add_argument("--out", required=True, help="model file to write")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--report", help="also write the metadata as JSON here")
    args = ap.parse_args(argv)
    meta = train(args.data, args.out, args.seed)
    print(json.dumps({k: meta[k] for k in ("rows", "rows_per_class", "arms", "holdout")}, indent=2))
    if args.report:
        with open(args.report, "w") as f:
            json.dump(meta, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
