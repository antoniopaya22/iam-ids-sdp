# Derived from Apollon, MAB/apollon_mab.py (https://github.com/antoniopaya22/apollon),
# Copyright the Apollon authors, licensed under the Apache License, Version 2.0.
# See ids/third_party/apollon/LICENSE and NOTICE for the license text and the list of
# changes made for iam-ids-sdp.
"""Apollon: per-cluster Multi-Armed Bandit with Thompson sampling over a pool of classifiers.

How it works (Payá et al., Computers & Security 136, 103546, 2024):

1. Inputs are grouped with K-Means; every arm (classifier) is trained per cluster.
2. Each (cluster, arm) pair keeps a Beta posterior over the arm's probability of classifying
   an input correctly, initialised from a held-out validation split.
3. For every input, Thompson sampling draws one value per arm from its posterior and the arm
   with the highest draw answers. The answering classifier changes from input to input, which
   is what makes the decision boundary hard for an adversary to learn.
4. When ground truth becomes available (e.g. analyst feedback), ``update`` adds the observed
   successes and failures to the posteriors.
"""

from __future__ import annotations

import numpy as np
from sklearn.base import clone
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier


def default_arms(random_state=None):
    """The classifier families of the Apollon paper (RF, DT, NB, LR, MLP), sized for the lab."""
    return [
        RandomForestClassifier(n_estimators=50, max_depth=8, random_state=random_state, n_jobs=1),
        DecisionTreeClassifier(max_depth=6, random_state=random_state),
        GaussianNB(),
        LogisticRegression(max_iter=1000),
        MLPClassifier(hidden_layer_sizes=(16,), max_iter=500, activation="tanh", solver="adam",
                      random_state=random_state),
    ]


class ApollonMAB:
    """Per-cluster Thompson-sampling selection over a pool of binary classifiers.

    Parameters
    ----------
    arms:
        Unfitted scikit-learn classifiers. Defaults to :func:`default_arms`.
    n_clusters:
        Number of K-Means clusters (the paper uses 2).
    val_size:
        Fraction of the training data held out to initialise the Beta posteriors.
    prior_strength:
        If set, the validation counts of each (cluster, arm) are rescaled to this many
        pseudo-observations. ``None`` uses the raw counts.
    random_state:
        Seed for the split, K-Means, the arms and the Thompson draws.
    """

    def __init__(self, arms=None, n_clusters=2, val_size=0.2, prior_strength=None,
                 random_state=None):
        self.arms = arms if arms is not None else default_arms(random_state)
        self.n_arms = len(self.arms)
        self.n_clusters = n_clusters
        self.val_size = val_size
        self.prior_strength = prior_strength
        self.random_state = random_state
        self.rng = np.random.default_rng(random_state)

    # ------------------------------------------------------------------ training

    def fit(self, X, y):
        X = np.asarray(X, dtype=float)
        y = np.asarray(y).astype(int)
        X_fit, X_val, y_fit, y_val = train_test_split(
            X, y, test_size=self.val_size, random_state=self.random_state, stratify=y)

        self.kmeans_ = KMeans(n_clusters=self.n_clusters, n_init=10,
                              random_state=self.random_state).fit(X_fit)
        c_fit = self.kmeans_.labels_
        c_val = self.kmeans_.predict(X_val)

        # models_[c][a] is arm a trained on cluster c.
        self.models_ = []
        self.fallback_ = np.zeros((self.n_clusters, self.n_arms), dtype=bool)
        global_models = None
        for c in range(self.n_clusters):
            m = c_fit == c
            row = []
            for a, arm in enumerate(self.arms):
                if len(np.unique(y_fit[m])) > 1:
                    row.append(clone(arm).fit(X_fit[m], y_fit[m]))
                else:
                    # A cluster with a single class cannot train a classifier: use the arm
                    # trained on all data for that cluster.
                    if global_models is None:
                        global_models = [clone(a_).fit(X_fit, y_fit) for a_ in self.arms]
                    row.append(global_models[a])
                    self.fallback_[c, a] = True
            self.models_.append(row)

        # Beta posteriors initialised from validation accuracy per (cluster, arm).
        self.alpha_ = np.ones((self.n_clusters, self.n_arms))
        self.beta_ = np.ones((self.n_clusters, self.n_arms))
        for c in range(self.n_clusters):
            m = c_val == c
            n = int(m.sum())
            if n == 0:
                continue
            for a in range(self.n_arms):
                correct = float(np.sum(self.models_[c][a].predict(X_val[m]) == y_val[m]))
                scale = 1.0 if self.prior_strength is None else self.prior_strength / n
                self.alpha_[c, a] += correct * scale
                self.beta_[c, a] += (n - correct) * scale
        return self

    # ------------------------------------------------------------------ selection

    def select_arms(self, X):
        """Cluster and Thompson-selected arm for every row of X."""
        X = np.asarray(X, dtype=float)
        clusters = self.kmeans_.predict(X)
        theta = self.rng.beta(self.alpha_[clusters], self.beta_[clusters])
        return clusters, np.argmax(theta, axis=1)

    def _route(self, X, method):
        X = np.asarray(X, dtype=float)
        clusters, arms = self.select_arms(X)
        out = None
        for c in range(self.n_clusters):
            for a in range(self.n_arms):
                m = (clusters == c) & (arms == a)
                if not m.any():
                    continue
                res = getattr(self.models_[c][a], method)(X[m])
                if out is None:
                    out = np.zeros((len(X),) + res.shape[1:], dtype=float)
                out[m] = res
        return out, clusters, arms

    def predict(self, X, return_arms=False):
        y, clusters, arms = self._route(X, "predict")
        y = y.astype(int)
        return (y, arms) if return_arms else y

    def predict_proba(self, X):
        """Class probabilities from the arm selected for each row (one draw per row)."""
        return self._route(X, "predict_proba")[0]

    def predict_proba_with_arms(self, X):
        """Like predict_proba, also returning the cluster and arm that answered each row."""
        return self._route(X, "predict_proba")

    def arm_names(self):
        return [type(a).__name__ for a in self.arms]

    # ------------------------------------------------------------------ feedback

    def update(self, X, y_true, clusters=None, arms=None, y_pred=None):
        """Thompson-sampling update with ground truth for already answered inputs.

        Pass the ``clusters``/``arms`` returned when the inputs were answered (and the
        predictions). Without them, the inputs are answered again now.
        """
        y_true = np.asarray(y_true).astype(int)
        if clusters is None or arms is None or y_pred is None:
            y_pred, arms = self.predict(X, return_arms=True)
            clusters = self.kmeans_.predict(np.asarray(X, dtype=float))
        correct = (np.asarray(y_pred) == y_true).astype(float)
        np.add.at(self.alpha_, (np.asarray(clusters), np.asarray(arms)), correct)
        np.add.at(self.beta_, (np.asarray(clusters), np.asarray(arms)), 1.0 - correct)
        return self

    def selection_frequencies(self, X, n_draws=1):
        """Share of inputs answered by each arm (useful to report the arm mix)."""
        counts = np.zeros(self.n_arms)
        for _ in range(n_draws):
            counts += np.bincount(self.select_arms(X)[1], minlength=self.n_arms)
        return counts / counts.sum()
