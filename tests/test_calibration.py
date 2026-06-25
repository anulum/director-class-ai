# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — calibration tests

from __future__ import annotations

import pytest

from director_class_ai.core import (
    CalibrationRegistry,
    DetectorSignal,
    EvaluationRequest,
    Locus,
    ParallelEnsembleScorer,
    Plane,
    PlattCalibrator,
    fit_platt,
)


class TestPlattCalibrator:
    def test_sigmoid_midpoint(self) -> None:
        assert PlattCalibrator(a=1.0, b=0.0).calibrate(0.0) == pytest.approx(0.5)

    def test_extremes_are_stable_and_bounded(self) -> None:
        c = PlattCalibrator(a=10.0, b=0.0)
        assert 0.0 <= c.calibrate(-100.0) < 1e-6
        assert 1.0 - c.calibrate(100.0) < 1e-6

    def test_monotonic(self) -> None:
        c = PlattCalibrator(a=2.0, b=-1.0)
        assert c.calibrate(0.2) < c.calibrate(0.8)


class TestFitPlatt:
    def test_fit_learns_separation(self) -> None:
        # low scores -> label 0, high scores -> label 1
        scores = [0.05, 0.1, 0.15, 0.2, 0.8, 0.85, 0.9, 0.95]
        labels = [0, 0, 0, 0, 1, 1, 1, 1]
        cal = fit_platt(scores, labels)
        assert cal.calibrate(0.1) < 0.5 < cal.calibrate(0.9)

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            fit_platt([0.1, 0.2], [1])

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            fit_platt([], [])

    def test_all_one_class_does_not_crash(self) -> None:
        cal = fit_platt([0.3, 0.4, 0.5], [0, 0, 0])
        assert 0.0 <= cal.calibrate(0.4) <= 1.0


def _sig(detector: str, score: float) -> DetectorSignal:
    return DetectorSignal(
        detector=detector,
        plane=Plane.CONTENT,
        score=score,
        locus=Locus.RESPONSE,
        signal_type="t",
    )


class TestCalibrationRegistry:
    def test_apply_rescales_registered_detector(self) -> None:
        reg = CalibrationRegistry()
        reg.set("d", PlattCalibrator(a=0.0, b=0.0))  # always 0.5
        out = reg.apply(_sig("d", 0.9))
        assert out.score == pytest.approx(0.5)
        assert out.detector == "d"

    def test_unregistered_detector_passes_through(self) -> None:
        reg = CalibrationRegistry()
        sig = _sig("other", 0.9)
        assert reg.apply(sig) is sig
        assert reg.has("other") is False

    def test_has_reports_registration(self) -> None:
        reg = CalibrationRegistry()
        reg.set("d", PlattCalibrator(1.0, 0.0))
        assert reg.has("d") is True


class _FixedDetector:
    name = "fixed"
    plane = Plane.CONTENT
    tier = 0

    def __init__(self, score: float) -> None:
        self._score = score

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal:
        return _sig(self.name, self._score)


def test_ensemble_applies_calibration_before_fusion() -> None:
    # raw 0.9 would flag content (>=0.5); calibrate it down to ~0.27 so it allows
    reg = CalibrationRegistry()
    reg.set("fixed", PlattCalibrator(a=0.0, b=-1.0))  # constant σ(-1) ≈ 0.269
    ens = ParallelEnsembleScorer([_FixedDetector(0.9)], calibration=reg)
    v = ens.evaluate(EvaluationRequest(response="x"))
    assert v.plane_risk[Plane.CONTENT] == pytest.approx(0.269, abs=1e-2)
    assert v.allow is True


def test_ensemble_without_calibration_uses_raw() -> None:
    ens = ParallelEnsembleScorer([_FixedDetector(0.9)])
    v = ens.evaluate(EvaluationRequest(response="x"))
    assert v.allow is False  # raw 0.9 >= 0.5
