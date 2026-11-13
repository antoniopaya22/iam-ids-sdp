import csv
import time

import pytest

from sdp_ids import dataset
from sdp_ids.detector import Detector
from sdp_ids.server import IDS, Recorder, peer_ou
from conftest import window
from test_detector import FixedModel


class FakeSink:
    def __init__(self):
        self.sent = []

    def send(self, alert):
        self.sent.append(alert)
        return {"action": "revoked", "revoked": [alert["session_id"]]}


def test_peer_ou():
    cert = {"subject": ((("organizationName", "lab"),), (("organizationalUnitName", "gateway"),),
                        (("commonName", "sdp-gateway"),))}
    assert peer_ou(cert) == ("sdp-gateway", "gateway")
    assert peer_ou(None) == ("", "")


def test_batch_to_alert_to_controller(rng, tmp_path):
    sink = FakeSink()
    ids = IDS(Detector(FixedModel(), consecutive=2), sink, enforce=True, recorder=Recorder(str(tmp_path / "rec.csv")))
    batch = {"feature_set": "sdp-window-v1", "windows": [window(rate=1, rng=rng) for _ in range(5)]}
    assert ids.handle_batch(batch) == 5
    for _ in range(2):
        ids.handle_batch({"feature_set": "sdp-window-v1", "windows": [window(rate=900, rng=rng)]})
    deadline = time.time() + 5
    while not ids.status()["alerts"][0]["enforced"] and time.time() < deadline:
        time.sleep(0.01)
    assert len(sink.sent) == 1 and sink.sent[0]["session_id"] == "s1"
    assert sink.sent[0]["detector"] == "apollon-mab+ueba"
    st = ids.status()
    assert st["counters"]["alerts"] == 1 and st["alerts"][0]["enforced"]
    with open(tmp_path / "rec.csv") as f:
        assert len(list(csv.DictReader(f))) == 7


def test_observe_only_mode_does_not_call_the_controller(rng):
    sink = FakeSink()
    ids = IDS(Detector(FixedModel(), consecutive=1), sink, enforce=False, recorder=None)
    ids.handle_batch({"feature_set": "sdp-window-v1", "windows": [window(rate=900, rng=rng)]})
    assert sink.sent == [] and ids.status()["counters"]["alerts"] == 1


def test_rejects_unknown_feature_set():
    ids = IDS(Detector(None), None, enforce=False, recorder=None)
    with pytest.raises(ValueError):
        ids.handle_batch({"feature_set": "v0", "windows": []})


def test_label_joins_the_manifest(tmp_path, rng):
    raw = tmp_path / "raw.csv"
    rec = Recorder(str(raw))
    rec.write(window(session="a", rate=2, rng=rng))
    rec.write(window(session="b", rate=500, rng=rng))
    rec.write(window(session="zzz", rate=5, rng=rng))
    man = tmp_path / "manifest.csv"
    man.write_text("session_id,profile,label\na,browse,0\nb,hey-c1,1\n")
    out = tmp_path / "out.csv"
    assert dataset.label(str(raw), str(man), str(out)) == 2
    rows = list(csv.DictReader(open(out)))
    assert [r["label"] for r in rows] == ["0", "1"]
