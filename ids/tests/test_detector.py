from sdp_ids import train, model as model_io
from sdp_ids.detector import Detector
from conftest import window


class FixedModel:
    """Stand-in classifier: anomalous above a request rate."""
    ueba_prior = None
    meta = {}
    arms = ["Fixed"]

    def predict(self, X):
        import math
        rate = math.expm1(X[0][0])
        return [0.99 if rate > 50 else 0.01], ["Fixed"]


def test_alert_needs_consecutive_anomalous_windows_and_fires_once(rng):
    det = Detector(FixedModel(), consecutive=2)
    for _ in range(10):
        assert not det.process(window(rate=1.0, rng=rng)).anomalous
    d1 = det.process(window(rate=500, rng=rng))
    assert d1.anomalous and not d1.alert and d1.streak == 1
    d2 = det.process(window(rate=500, rng=rng))
    assert d2.alert and "alice" in d2.reason and "Fixed" in d2.reason
    d3 = det.process(window(rate=500, rng=rng))
    assert d3.anomalous and not d3.alert  # one alert per session
    assert det.counters["alerts"] == 1
    det.forget_alert("s1")
    assert det.process(window(rate=500, rng=rng)).alert


def test_policy_both_requires_agreement(rng):
    det = Detector(FixedModel(), consecutive=1)
    # A heavy-but-usual identity: the classifier fires, the baseline does not.
    for _ in range(40):
        det.ueba.update("robot", {"req_rate": 400, "bytes_out_rate": 240000})
    d = det.process(window(user="robot", rate=400, rng=rng))
    assert d.classifier_anomalous and not d.ueba_deviates and not d.anomalous


def test_flagged_windows_are_not_learnt(rng):
    det = Detector(FixedModel(), consecutive=5)
    for _ in range(5):
        det.process(window(rate=1.0, rng=rng))
    learnt = det.ueba.snapshot()["alice"]["windows_learnt"]
    for _ in range(3):
        det.process(window(rate=800, rng=rng))
    assert det.ueba.snapshot()["alice"]["windows_learnt"] == learnt


def test_with_a_trained_model(tmp_path, labelled_csv, rng):
    out = tmp_path / "m.joblib"
    train.train([labelled_csv], str(out), seed=3)
    det = Detector(model_io.load(str(out)), consecutive=2)
    for i in range(15):
        assert not det.process(window(session="bench", user="bench", rate=10, rng=rng)).anomalous
        assert not det.process(window(rate=1.5, rng=rng)).anomalous
    alerts = [det.process(window(rate=600, rng=rng, conns=10)).alert for _ in range(3)]
    assert alerts.count(True) == 1
