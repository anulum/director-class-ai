# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — learned signal meta-classifier

"""Pure-Python learned fusion policy for calibrated detector signals.

The default fusion path remains transparent noisy-OR. This module provides the
production hook for the Phase 3 learned meta-classifier lane: train a small sparse
logistic model over groups of :class:`DetectorSignal` objects, serialize it as
plain JSON-compatible data, and opt into it through ``MetaClassifierFusionPolicy``
when an offline validation run justifies the switch.
"""

from __future__ import annotations

import importlib
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TypeAlias

from .fusion import FusionPolicy
from .signal import DetectorSignal

__all__ = [
    "MetaClassifierFusionPolicy",
    "SignalMetaClassifier",
    "extract_signal_features",
    "fit_signal_meta_classifier",
]

_MODEL_VERSION = 1
_RUST_FLOAT_TOLERANCE = 1e-12
_RustSignalRow: TypeAlias = tuple[str, float, str, str, str, float]
_FeatureItems: TypeAlias = list[tuple[str, float]]
_RustExtractFeatures: TypeAlias = Callable[[Sequence[_RustSignalRow]], _FeatureItems]
_RustRisk: TypeAlias = Callable[
    [Sequence[tuple[str, float]], float, Sequence[tuple[str, float]]], float
]
_RustFit: TypeAlias = Callable[
    [Sequence[tuple[_FeatureItems, int]], int, float, float],
    tuple[_FeatureItems, float],
]


def _load_rust_extract_features() -> _RustExtractFeatures | None:
    try:
        module = importlib.import_module("director_class_ai._rust")
    except ImportError:
        return None
    extract = getattr(module, "meta_extract_signal_features", None)
    return extract if callable(extract) else None


def _load_rust_risk() -> _RustRisk | None:
    try:
        module = importlib.import_module("director_class_ai._rust")
    except ImportError:
        return None
    risk = getattr(module, "meta_risk", None)
    return risk if callable(risk) else None


def _load_rust_fit() -> _RustFit | None:
    try:
        module = importlib.import_module("director_class_ai._rust")
    except ImportError:
        return None
    fit = getattr(module, "meta_fit", None)
    return fit if callable(fit) else None


_RUST_EXTRACT_FEATURES = _load_rust_extract_features()
_RUST_RISK = _load_rust_risk()
_RUST_FIT = _load_rust_fit()


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _close(left: float, right: float) -> bool:
    return math.isclose(
        left, right, rel_tol=_RUST_FLOAT_TOLERANCE, abs_tol=_RUST_FLOAT_TOLERANCE
    )


def _require_probability(value: float, *, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {value}")


def _rust_signal_rows(signals: Sequence[DetectorSignal]) -> list[_RustSignalRow]:
    return [
        (
            signal.detector,
            signal.weighted_score,
            signal.signal_type,
            signal.locus.value,
            signal.severity.name.lower(),
            float(signal.severity),
        )
        for signal in signals
    ]


def _features_equal(left: Mapping[str, float], right: Mapping[str, float], /) -> bool:
    return left.keys() == right.keys() and all(
        _close(left[name], right[name]) for name in left
    )


def _extract_signal_features_python(
    signals: Sequence[DetectorSignal],
) -> dict[str, float]:
    features = {
        "signal_count": float(len(signals)),
        "max_score": 0.0,
        "sum_score": 0.0,
        "mean_score": 0.0,
        "max_severity": 0.0,
    }
    if not signals:
        return features

    total = 0.0
    max_score = 0.0
    max_severity = 0.0
    for signal in signals:
        score = signal.weighted_score
        _require_probability(score, name=f"{signal.detector}.weighted_score")
        total += score
        max_score = max(max_score, score)
        max_severity = max(max_severity, float(signal.severity))
        for prefix, value in (
            ("detector", signal.detector),
            ("signal_type", signal.signal_type),
            ("locus", signal.locus.value),
            ("severity", signal.severity.name.lower()),
        ):
            key = f"{prefix}:{value}"
            features[key] = max(features.get(key, 0.0), score)

    features["max_score"] = max_score
    features["sum_score"] = min(total, float(len(signals)))
    features["mean_score"] = total / len(signals)
    features["max_severity"] = max_severity / 4.0
    return features


def extract_signal_features(signals: Sequence[DetectorSignal]) -> dict[str, float]:
    """Convert detector signals into stable sparse features."""
    python_features = _extract_signal_features_python(signals)
    if _RUST_EXTRACT_FEATURES is None:
        return python_features
    try:
        rust_features = dict(_RUST_EXTRACT_FEATURES(_rust_signal_rows(signals)))
    except Exception:
        return python_features
    return (
        rust_features
        if _features_equal(python_features, rust_features)
        else python_features
    )


@dataclass(frozen=True)
class SignalMetaClassifier:
    """Sparse logistic risk model over one plane's detector signals."""

    weights: Mapping[str, float] = field(default_factory=dict)
    bias: float = 0.0

    def __post_init__(self) -> None:
        if not math.isfinite(self.bias):
            raise ValueError("bias must be finite")
        for key, value in self.weights.items():
            if not key:
                raise ValueError("feature names must be non-empty")
            if not math.isfinite(value):
                raise ValueError(f"weight for {key!r} must be finite")

    def risk(self, signals: Sequence[DetectorSignal]) -> float:
        """Return ``P(problem)`` for a group of signals."""
        features = extract_signal_features(signals)
        z = self.bias
        for name, value in features.items():
            z += self.weights.get(name, 0.0) * value
        python_risk = _sigmoid(z)
        if _RUST_RISK is None:
            return python_risk
        try:
            rust_risk = _RUST_RISK(
                list(self.weights.items()), self.bias, list(features.items())
            )
        except Exception:
            return python_risk
        return rust_risk if _close(python_risk, rust_risk) else python_risk

    def to_dict(self) -> dict[str, object]:
        """Serialize to a deterministic JSON-compatible mapping."""
        return {
            "version": _MODEL_VERSION,
            "bias": self.bias,
            "weights": dict(sorted(self.weights.items())),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> SignalMetaClassifier:
        """Load a serialized classifier, rejecting unknown model versions."""
        if payload.get("version") != _MODEL_VERSION:
            raise ValueError(
                f"unsupported meta-classifier version: {payload.get('version')}"
            )
        raw_weights = payload.get("weights")
        if not isinstance(raw_weights, Mapping):
            raise ValueError("weights must be a mapping")
        weights: dict[str, float] = {}
        for key, value in raw_weights.items():
            if not isinstance(key, str) or not isinstance(value, int | float):
                raise ValueError("weights must map string feature names to numbers")
            weights[key] = float(value)
        bias = payload.get("bias", 0.0)
        if not isinstance(bias, int | float):
            raise ValueError("bias must be numeric")
        return cls(weights=weights, bias=float(bias))


def fit_signal_meta_classifier(
    observations: Sequence[tuple[Sequence[DetectorSignal], int]],
    *,
    iters: int = 2000,
    lr: float = 0.2,
    l2: float = 0.001,
) -> SignalMetaClassifier:
    """Fit a sparse logistic meta-classifier from labelled signal groups."""
    if not observations:
        raise ValueError("need at least one observation to fit")
    if iters <= 0:
        raise ValueError("iters must be positive")
    if lr <= 0.0:
        raise ValueError("lr must be positive")
    if l2 < 0.0:
        raise ValueError("l2 must be non-negative")

    rows: list[tuple[dict[str, float], int]] = []
    feature_names: set[str] = set()
    for signals, label in observations:
        if label not in (0, 1):
            raise ValueError("labels must be 0 or 1")
        features = extract_signal_features(signals)
        rows.append((features, label))
        feature_names.update(features)

    python_model = _fit_signal_meta_classifier_python(
        rows, feature_names, iters=iters, lr=lr, l2=l2
    )
    if _RUST_FIT is None:
        return python_model
    try:
        raw_weights, rust_bias = _RUST_FIT(
            [(list(features.items()), label) for features, label in rows], iters, lr, l2
        )
        rust_model = SignalMetaClassifier(weights=dict(raw_weights), bias=rust_bias)
    except Exception:
        return python_model
    return (
        rust_model
        if _model_matches_rows(python_model, rust_model, rows)
        else python_model
    )


def _fit_signal_meta_classifier_python(
    rows: Sequence[tuple[dict[str, float], int]],
    feature_names: set[str],
    *,
    iters: int,
    lr: float,
    l2: float,
) -> SignalMetaClassifier:
    """Fit the Python reference model over prevalidated feature rows."""
    weights = dict.fromkeys(sorted(feature_names), 0.0)
    bias = 0.0
    n = float(len(rows))
    for _ in range(iters):
        grad = dict.fromkeys(weights, 0.0)
        grad_bias = 0.0
        for features, label in rows:
            z = bias + sum(weights[name] * value for name, value in features.items())
            err = _sigmoid(z) - label
            grad_bias += err
            for name, value in features.items():
                grad[name] += err * value
        bias -= lr * grad_bias / n
        for name in weights:
            weights[name] -= lr * ((grad[name] / n) + (l2 * weights[name]))

    return SignalMetaClassifier(weights=weights, bias=bias)


def _model_matches_rows(
    left: SignalMetaClassifier,
    right: SignalMetaClassifier,
    rows: Sequence[tuple[dict[str, float], int]],
) -> bool:
    """Return whether two fitted models agree on the validated training rows."""
    if left.weights.keys() != right.weights.keys():
        return False
    if not all(_close(left.weights[name], right.weights[name]) for name in left.weights):
        return False
    if not _close(left.bias, right.bias):
        return False
    for features, _label in rows:
        left_z = left.bias + sum(
            left.weights.get(name, 0.0) * value for name, value in features.items()
        )
        right_z = right.bias + sum(
            right.weights.get(name, 0.0) * value for name, value in features.items()
        )
        if not _close(_sigmoid(left_z), _sigmoid(right_z)):
            return False
    return True


@dataclass
class MetaClassifierFusionPolicy(FusionPolicy):
    """Fusion policy that replaces noisy-OR with a learned model."""

    meta_classifier: SignalMetaClassifier = field(default_factory=SignalMetaClassifier)

    def content_risk(self, signals: Sequence[DetectorSignal]) -> float:
        """Fuse content/integrity signals through the learned meta-classifier."""
        return self.meta_classifier.risk(signals)
