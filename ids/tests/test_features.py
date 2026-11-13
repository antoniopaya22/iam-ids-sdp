import math
import os
import re

from sdp_ids.features import FEATURE_NAMES, vectorize

GO_FEATURES = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "gateway", "features.go")


def test_feature_names_match_the_gateway():
    with open(GO_FEATURES) as f:
        src = f.read()
    block = src[src.index("var FeatureNames"):]
    block = block[:block.index("}")]
    assert re.findall(r'"([a-z_]+)"', block) == FEATURE_NAMES


def test_vectorize_order_and_transform():
    feats = {name: 1.0 for name in FEATURE_NAMES}
    feats["req_rate"] = 99.0
    feats["iat_cv"] = 0.7
    v = vectorize(feats)
    assert len(v) == len(FEATURE_NAMES)
    assert math.isclose(v[FEATURE_NAMES.index("req_rate")], math.log1p(99.0))
    assert math.isclose(v[FEATURE_NAMES.index("iat_cv")], 0.7)  # ratios stay linear


def test_vectorize_sanitises_bad_values():
    v = vectorize({"req_rate": float("nan"), "bytes_in_rate": -5, "bytes_out_rate": "x", "open_conns": float("inf")})
    assert all(x == 0.0 for x in v)
