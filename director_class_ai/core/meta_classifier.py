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

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .fusion import FusionPolicy
from .signal import DetectorSignal

__all__ = [
    "MetaClassifierFusionPolicy",
    "SignalMetaClassifier",
    "extract_signal_features",
    "fit_signal_meta_classifier",
]

_MODEL_VERSION = 1


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def _require_probability(value: float, *, name: str) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {value}")


def extract_signal_features(signals: Sequence[DetectorSignal]) -> dict[str, float]:
    """Convert detector signals into stable sparse features."""
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
        return _sigmoid(z)

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


@dataclass
class MetaClassifierFusionPolicy(FusionPolicy):
    """Fusion policy that replaces noisy-OR with a learned model."""

    meta_classifier: SignalMetaClassifier = field(default_factory=SignalMetaClassifier)

    def content_risk(self, signals: Sequence[DetectorSignal]) -> float:
        """Fuse content/integrity signals through the learned meta-classifier."""
        return self.meta_classifier.risk(signals)
