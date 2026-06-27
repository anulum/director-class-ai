# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — per-detector score calibration

"""Map each detector's raw score onto a true probability so fusion is honest.

The ablation that motivated this product showed why it matters: fusing a strong
detector with a weak one by raw noisy-OR *hurt* the result, because the two
detectors' scores were not on the same probability scale. Calibration fixes that
— Platt scaling fits a per-detector logistic ``σ(a·raw + b)`` from labelled
outcomes, so a "0.9" from one detector and a "0.9" from another both mean the same
empirical probability of being right. Calibrated scores are what the fusion layer
should combine.

The runtime is pure Python (a stable sigmoid), so the lean zero-dependency core
can apply a calibration anywhere. The fit is also pure Python (Platt's regularised
logistic objective by gradient descent), so even fitting needs no numpy.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from .signal import DetectorSignal

__all__ = ["PlattCalibrator", "CalibrationRegistry", "fit_platt"]


def _sigmoid(z: float) -> float:
    """Numerically stable logistic sigmoid."""
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass(frozen=True)
class PlattCalibrator:
    """Logistic map ``σ(a·raw + b)`` from a raw detector score to a probability."""

    a: float
    b: float

    def calibrate(self, raw: float) -> float:
        """Map one raw detector score onto the calibrated probability scale."""
        return _sigmoid(self.a * raw + self.b)


def fit_platt(
    scores: Sequence[float],
    labels: Sequence[int],
    *,
    iters: int = 2000,
    lr: float = 0.5,
) -> PlattCalibrator:
    """Fit Platt scaling on (raw score, label) pairs — pure-Python, no numpy.

    Uses Platt's regularised targets (``t+ = (N+ +1)/(N+ +2)``, ``t- = 1/(N- +2)``)
    so the fit does not over-confidently saturate on small samples.
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels must be the same length")
    if not scores:
        raise ValueError("need at least one observation to fit")
    n_pos = sum(1 for y in labels if y == 1)
    n_neg = len(labels) - n_pos
    hi = (n_pos + 1.0) / (n_pos + 2.0)
    lo = 1.0 / (n_neg + 2.0)
    targets = [hi if y == 1 else lo for y in labels]

    a, b = 0.0, 0.0
    n = float(len(scores))
    for _ in range(iters):
        ga = gb = 0.0
        for s, t in zip(scores, targets, strict=True):
            p = _sigmoid(a * s + b)
            err = p - t
            ga += err * s
            gb += err
        a -= lr * ga / n
        b -= lr * gb / n
    return PlattCalibrator(a, b)


class CalibrationRegistry:
    """Per-detector calibrators; rescores a signal's score onto its probability."""

    def __init__(self) -> None:
        self._by_detector: dict[str, PlattCalibrator] = {}

    def set(self, detector: str, calibrator: PlattCalibrator) -> None:
        """Install or replace the calibrator for one detector name."""
        self._by_detector[detector] = calibrator

    def has(self, detector: str) -> bool:
        """Return whether a detector has a fitted calibrator."""
        return detector in self._by_detector

    def apply(self, signal: DetectorSignal) -> DetectorSignal:
        """Return *signal* with its score replaced by the calibrated probability.

        Detectors without a fitted calibrator pass through unchanged.
        """
        calibrator = self._by_detector.get(signal.detector)
        if calibrator is None:
            return signal
        calibrated = calibrator.calibrate(signal.score)
        return DetectorSignal(
            detector=signal.detector,
            plane=signal.plane,
            score=calibrated,
            locus=signal.locus,
            signal_type=signal.signal_type,
            severity=signal.severity,
            calibration=1.0,
            spans=signal.spans,
            rationale=signal.rationale,
            latency_ms=signal.latency_ms,
        )
