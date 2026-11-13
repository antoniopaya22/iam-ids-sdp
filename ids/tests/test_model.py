import pickle
import sys
import types

import numpy as np

from sdp_ids import apollon_mab, model as model_io, train
from sdp_ids.features import vectorize
from conftest import window_features


def test_train_load_predict(tmp_path, labelled_csv, rng):
    out = tmp_path / "m.joblib"
    meta = train.train([labelled_csv], str(out), seed=3)
    assert meta["rows_per_class"] == {"0": 160, "1": 80}
    assert meta["holdout"]["accuracy"] > 0.95
    m = model_io.load(str(out))
    assert set(m.ueba_prior) == {"req_rate", "bytes_out_rate"}
    low = np.vstack([vectorize(window_features(2, rng)) for _ in range(20)])
    high = np.vstack([vectorize(window_features(800, rng, 5)) for _ in range(20)])
    p_low, arms = m.predict(low)
    p_high, _ = m.predict(high)
    assert (p_low < 0.5).mean() > 0.9 and (p_high >= 0.5).mean() > 0.9
    assert all(a in m.arms for a in arms)


def test_bare_apollon_pickle_is_accepted(tmp_path, labelled_csv, rng):
    """A model pickled by the Apollon repository refers to MAB.apollon_mab.ApollonMAB."""
    from sdp_ids.dataset import read_labelled
    from sdp_ids.features import vectorize_many

    feats, y, _ = read_labelled([labelled_csv])
    X = vectorize_many(feats)

    fake_pkg = types.ModuleType("MAB")
    fake_mod = types.ModuleType("MAB.apollon_mab")
    cls = type("ApollonMAB", (apollon_mab.ApollonMAB,), {"__module__": "MAB.apollon_mab"})
    fake_mod.ApollonMAB = cls
    sys.modules["MAB"], sys.modules["MAB.apollon_mab"] = fake_pkg, fake_mod
    try:
        est = cls(random_state=0).fit(X, y)
        path = tmp_path / "apollon.pkl"
        with open(path, "wb") as f:
            pickle.dump(est, f)
    finally:
        del sys.modules["MAB"], sys.modules["MAB.apollon_mab"]

    m = model_io.load(str(path))
    assert m.scaler is None and m.ueba_prior is None
    p, arms = m.predict(np.vstack([vectorize(window_features(900, rng, 5))]))
    assert p[0] >= 0.5 and arms[0] in m.arms
