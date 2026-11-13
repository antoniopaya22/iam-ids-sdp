import numpy as np

from sdp_ids.apollon_mab import ApollonMAB


def data(rng, n=200):
    X0 = rng.normal(0, 1, size=(n, 3))
    X1 = rng.normal(4, 1, size=(n, 3))
    return np.vstack([X0, X1]), np.array([0] * n + [1] * n)


def test_thompson_sampling_spreads_answers_over_the_pool(rng):
    X, y = data(rng)
    mab = ApollonMAB(random_state=1).fit(X, y)
    proba, clusters, arms = mab.predict_proba_with_arms(X)
    assert proba.shape == (len(X), 2)
    assert len(set(arms.tolist())) > 1, "a single arm answered every input"
    assert (np.argmax(proba, axis=1) == y).mean() > 0.95
    assert mab.arm_names()[0] == "RandomForestClassifier"


def test_update_moves_the_posteriors(rng):
    X, y = data(rng)
    mab = ApollonMAB(random_state=1).fit(X, y)
    before = (mab.alpha_.copy(), mab.beta_.copy())
    y_pred, arms = mab.predict(X[:10], return_arms=True)
    clusters = mab.kmeans_.predict(X[:10])
    mab.update(X[:10], 1 - y[:10], clusters=clusters, arms=arms, y_pred=y_pred)  # all wrong
    assert np.isclose(mab.beta_.sum() - before[1].sum(), 10)
    assert np.isclose(mab.alpha_.sum(), before[0].sum())
