# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — learned meta-classifier tests

from __future__ import annotations

from typing import cast

import pytest

from director_class_ai.core import (
    DetectorSignal,
    Locus,
    MetaClassifierFusionPolicy,
    Plane,
    Severity,
    SignalMetaClassifier,
    extract_signal_features,
    fit_signal_meta_classifier,
    fuse,
)


def _sig(
    *,
    detector: str = "nli",
    score: float = 0.8,
    signal_type: str = "contradiction",
    severity: Severity = Severity.MEDIUM,
) -> DetectorSignal:
    return DetectorSignal(
        detector=detector,
        plane=Plane.CONTENT,
        score=score,
        locus=Locus.RESPONSE,
        signal_type=signal_type,
        severity=severity,
    )


def test_extract_signal_features_are_bounded_and_auditable() -> None:
    features = extract_signal_features(
        [
            _sig(detector="nli", score=0.8, signal_type="contradiction"),
            _sig(detector="span", score=0.3, signal_type="unsupported"),
        ]
    )

    assert features["signal_count"] == 2.0
    assert features["max_score"] == pytest.approx(0.8)
    assert features["mean_score"] == pytest.approx(0.55)
    assert features["detector:nli"] == pytest.approx(0.8)
    assert features["signal_type:unsupported"] == pytest.approx(0.3)
    assert features["severity:medium"] == pytest.approx(0.8)


def test_extract_signal_features_handles_empty_groups() -> None:
    assert extract_signal_features([]) == {
        "signal_count": 0.0,
        "max_score": 0.0,
        "sum_score": 0.0,
        "mean_score": 0.0,
        "max_severity": 0.0,
    }


def test_extract_signal_features_rejects_out_of_range_weighted_score() -> None:
    class _BadSignal:
        detector = "bad"
        weighted_score = 1.2

    with pytest.raises(ValueError, match="weighted_score"):
        extract_signal_features([cast(DetectorSignal, _BadSignal())])


def test_fit_signal_meta_classifier_learns_separation() -> None:
    observations = [
        ([_sig(score=0.08, signal_type="unsupported")], 0),
        ([_sig(score=0.12, signal_type="unsupported")], 0),
        ([_sig(score=0.18, signal_type="contradiction")], 0),
        ([_sig(score=0.82, signal_type="contradiction")], 1),
        ([_sig(score=0.88, signal_type="contradiction")], 1),
        ([_sig(score=0.95, signal_type="unsupported")], 1),
    ]

    model = fit_signal_meta_classifier(observations, iters=1500, lr=0.3)

    assert model.risk([_sig(score=0.9)]) > 0.5
    assert model.risk([_sig(score=0.1)]) < 0.5
    assert model.risk([_sig(score=0.9)]) > model.risk([_sig(score=0.1)])


def test_meta_classifier_serializes_deterministically() -> None:
    model = SignalMetaClassifier(
        weights={"max_score": 3.0, "detector:nli": 1.0}, bias=-2.0
    )

    payload = model.to_dict()
    restored = SignalMetaClassifier.from_dict(payload)

    assert payload["weights"] == {"detector:nli": 1.0, "max_score": 3.0}
    assert restored.risk([_sig(score=0.7)]) == pytest.approx(
        model.risk([_sig(score=0.7)])
    )


def test_meta_classifier_payload_validation() -> None:
    with pytest.raises(ValueError, match="bias"):
        SignalMetaClassifier(bias=float("inf"))
    with pytest.raises(ValueError, match="feature names"):
        SignalMetaClassifier(weights={"": 1.0})
    with pytest.raises(ValueError, match="unsupported"):
        SignalMetaClassifier.from_dict({"version": 999, "bias": 0.0, "weights": {}})
    with pytest.raises(ValueError, match="weights"):
        SignalMetaClassifier.from_dict({"version": 1, "bias": 0.0, "weights": []})
    with pytest.raises(ValueError, match="weights"):
        SignalMetaClassifier.from_dict({"version": 1, "bias": 0.0, "weights": {1: 1.0}})
    with pytest.raises(ValueError, match="bias"):
        SignalMetaClassifier.from_dict({"version": 1, "bias": "bad", "weights": {}})
    with pytest.raises(ValueError, match="finite"):
        SignalMetaClassifier(weights={"bad": float("inf")})


def test_fit_rejects_invalid_training_inputs() -> None:
    with pytest.raises(ValueError, match="at least one"):
        fit_signal_meta_classifier([])
    with pytest.raises(ValueError, match="labels"):
        fit_signal_meta_classifier([([_sig()], 2)])
    with pytest.raises(ValueError, match="iters"):
        fit_signal_meta_classifier([([_sig()], 1)], iters=0)
    with pytest.raises(ValueError, match="lr"):
        fit_signal_meta_classifier([([_sig()], 1)], lr=0.0)
    with pytest.raises(ValueError, match="l2"):
        fit_signal_meta_classifier([([_sig()], 1)], l2=-0.1)


def test_meta_classifier_fusion_policy_is_explicit_opt_in() -> None:
    signals = [_sig(score=0.9)]
    default = fuse(signals)
    policy = MetaClassifierFusionPolicy(
        meta_classifier=SignalMetaClassifier(weights={}, bias=-4.0)
    )
    learned = fuse(signals, policy)

    assert default.allow is False
    assert learned.allow is True
    assert learned.plane_risk[Plane.CONTENT] == pytest.approx(0.018, abs=0.001)
