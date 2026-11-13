import math

from sdp_ids.ueba import UEBA

PRIOR = {"req_rate": (math.log1p(3.0), 0.8), "bytes_out_rate": (math.log1p(2000.0), 1.5)}


def feats(rate, out=None):
    return {"req_rate": rate, "bytes_out_rate": out if out is not None else rate * 600}


def test_new_identity_starts_from_the_population_prior():
    u = UEBA(PRIOR)
    d = u.score("carol", feats(3))
    assert not d.deviates
    assert abs(d.details["req_rate"]["baseline"] - 3.0) < 1e-6


def test_learns_a_baseline_and_flags_a_large_increase():
    u = UEBA(PRIOR)
    for _ in range(20):
        u.update("alice", feats(1.0))
    snap = u.snapshot()["alice"]
    assert snap["windows_learnt"] == 20
    assert snap["req_rate"]["typical"] < 2.0
    assert not u.score("alice", feats(2.0)).deviates          # normal jitter
    d = u.score("alice", feats(400.0))
    assert d.deviates and d.feature in ("req_rate", "bytes_out_rate")
    assert d.ratio > 100 and d.z >= 4


def test_only_increases_are_flagged():
    u = UEBA(PRIOR)
    for _ in range(20):
        u.update("bob", feats(50.0))
    assert not u.score("bob", feats(0.1)).deviates


def test_baselines_are_per_identity():
    u = UEBA(PRIOR)
    for _ in range(30):
        u.update("heavy", feats(20.0))
        u.update("light", feats(0.5))
    assert not u.score("heavy", feats(25.0)).deviates
    assert u.score("light", feats(25.0)).deviates
