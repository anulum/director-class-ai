# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — learned meta-classifier tests

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import cast

import pytest

import director_class_ai.core.meta_classifier as meta_classifier
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


class TestRustMetaClassifierParity:
    def test_loader_ignores_missing_callables(self, monkeypatch) -> None:
        module = SimpleNamespace(
            meta_extract_signal_features=object(),
            meta_risk=object(),
            meta_fit=object(),
        )
        monkeypatch.setattr(importlib, "import_module", lambda _: module)

        assert meta_classifier._load_rust_extract_features() is None
        assert meta_classifier._load_rust_risk() is None
        assert meta_classifier._load_rust_fit() is None

    def test_loaders_return_none_when_extension_is_absent(self, monkeypatch) -> None:
        def missing_extension(_name: str) -> object:
            raise ImportError("extension absent")

        monkeypatch.setattr(importlib, "import_module", missing_extension)

        assert meta_classifier._load_rust_extract_features() is None
        assert meta_classifier._load_rust_risk() is None
        assert meta_classifier._load_rust_fit() is None

    def test_python_paths_are_used_when_rust_primitives_are_absent(
        self, monkeypatch
    ) -> None:
        signals = [_sig(score=0.7)]
        observations = [([_sig(score=0.1)], 0), ([_sig(score=0.9)], 1)]
        monkeypatch.setattr(meta_classifier, "_RUST_EXTRACT_FEATURES", None)
        monkeypatch.setattr(meta_classifier, "_RUST_RISK", None)
        monkeypatch.setattr(meta_classifier, "_RUST_FIT", None)

        assert meta_classifier.extract_signal_features(signals) == (
            meta_classifier._extract_signal_features_python(signals)
        )
        model = SignalMetaClassifier(weights={"max_score": 1.0}, bias=0.0)
        assert model.risk(signals) == pytest.approx(
            meta_classifier._sigmoid(
                model.weights["max_score"]
                * meta_classifier._extract_signal_features_python(signals)["max_score"]
            )
        )
        assert fit_signal_meta_classifier(observations, iters=20, lr=0.2) == (
            meta_classifier._fit_signal_meta_classifier_python(
                [
                    (meta_classifier._extract_signal_features_python(row), label)
                    for row, label in observations
                ],
                {
                    name
                    for row, _label in observations
                    for name in meta_classifier._extract_signal_features_python(row)
                },
                iters=20,
                lr=0.2,
                l2=0.001,
            )
        )

    def test_feature_mismatch_falls_back_to_python(self, monkeypatch) -> None:
        signals = [_sig(score=0.7)]
        monkeypatch.setattr(
            meta_classifier,
            "_RUST_EXTRACT_FEATURES",
            lambda _rows: [("signal_count", 999.0)],
        )

        assert meta_classifier.extract_signal_features(
            signals
        ) == meta_classifier._extract_signal_features_python(signals)

    def test_feature_exception_falls_back_to_python(self, monkeypatch) -> None:
        signals = [_sig(score=0.7)]

        def broken_extract(_rows):
            raise RuntimeError("boom")

        monkeypatch.setattr(meta_classifier, "_RUST_EXTRACT_FEATURES", broken_extract)
        assert meta_classifier.extract_signal_features(
            signals
        ) == meta_classifier._extract_signal_features_python(signals)

    def test_risk_mismatch_and_exception_fall_back_to_python(self, monkeypatch) -> None:
        model = SignalMetaClassifier(weights={"max_score": 3.0}, bias=-1.0)
        signals = [_sig(score=0.7)]
        expected = model.risk(signals)

        monkeypatch.setattr(meta_classifier, "_RUST_RISK", lambda _w, _b, _f: 0.0)
        assert model.risk(signals) == pytest.approx(expected)

        def broken_risk(_weights, _bias, _features):
            raise RuntimeError("boom")

        monkeypatch.setattr(meta_classifier, "_RUST_RISK", broken_risk)
        assert model.risk(signals) == pytest.approx(expected)

    def test_fit_mismatch_and_exception_fall_back_to_python(self, monkeypatch) -> None:
        observations = [([_sig(score=0.1)], 0), ([_sig(score=0.9)], 1)]
        expected = fit_signal_meta_classifier(observations, iters=20, lr=0.2)
        monkeypatch.setattr(
            meta_classifier,
            "_RUST_FIT",
            lambda _rows, _iters, _lr, _l2: ([("max_score", 999.0)], 0.0),
        )
        assert fit_signal_meta_classifier(observations, iters=20, lr=0.2) == expected

        def broken_fit(_rows, _iters, _lr, _l2):
            raise RuntimeError("boom")

        monkeypatch.setattr(meta_classifier, "_RUST_FIT", broken_fit)
        assert fit_signal_meta_classifier(observations, iters=20, lr=0.2) == expected

    def test_model_match_helper_rejects_structural_drift(self) -> None:
        rows = [({"max_score": 0.7}, 1)]
        reference = SignalMetaClassifier(weights={"max_score": 1.0}, bias=0.0)

        assert (
            meta_classifier._model_matches_rows(
                reference, SignalMetaClassifier(weights={"other": 1.0}, bias=0.0), rows
            )
            is False
        )
        assert (
            meta_classifier._model_matches_rows(
                reference,
                SignalMetaClassifier(weights={"max_score": 2.0}, bias=0.0),
                rows,
            )
            is False
        )
        assert (
            meta_classifier._model_matches_rows(
                reference,
                SignalMetaClassifier(weights={"max_score": 1.0}, bias=1.0),
                rows,
            )
            is False
        )
        assert (
            meta_classifier._model_matches_rows(
                SignalMetaClassifier(weights={"max_score": 0.0}, bias=0.0),
                SignalMetaClassifier(weights={"max_score": 0.0000000000005}, bias=0.0),
                [({"max_score": 1_000_000_000_000.0}, 1)],
            )
            is False
        )

    def test_model_match_helper_accepts_equivalent_models(self) -> None:
        rows = [({"max_score": 0.7}, 1)]
        model = SignalMetaClassifier(weights={"max_score": 1.0}, bias=0.0)

        assert meta_classifier._model_matches_rows(model, model, rows) is True

    def test_installed_rust_meta_primitives_match_python_when_present(self) -> None:
        if (
            meta_classifier._RUST_EXTRACT_FEATURES is None
            or meta_classifier._RUST_RISK is None
            or meta_classifier._RUST_FIT is None
        ):
            return
        signals = [
            _sig(detector="nli", score=0.8, signal_type="contradiction"),
            _sig(detector="span", score=0.3, signal_type="unsupported"),
        ]
        features = meta_classifier._extract_signal_features_python(signals)
        assert (
            dict(
                meta_classifier._RUST_EXTRACT_FEATURES(
                    meta_classifier._rust_signal_rows(signals)
                )
            )
            == features
        )

        model = SignalMetaClassifier(weights={"max_score": 3.0}, bias=-1.0)
        assert meta_classifier._RUST_RISK(
            list(model.weights.items()), model.bias, list(features.items())
        ) == pytest.approx(model.risk(signals))

        observations = [([_sig(score=0.1)], 0), ([_sig(score=0.9)], 1)]
        rows = [
            (meta_classifier._extract_signal_features_python(row_signals), label)
            for row_signals, label in observations
        ]
        rust_weights, rust_bias = meta_classifier._RUST_FIT(
            [(list(row_features.items()), label) for row_features, label in rows],
            20,
            0.2,
            0.001,
        )
        rust_model = SignalMetaClassifier(weights=dict(rust_weights), bias=rust_bias)
        python_model = meta_classifier._fit_signal_meta_classifier_python(
            rows,
            {name for row_features, _label in rows for name in row_features},
            iters=20,
            lr=0.2,
            l2=0.001,
        )
        assert meta_classifier._model_matches_rows(python_model, rust_model, rows)
