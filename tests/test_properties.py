# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — property-based (Hypothesis) invariants

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from director_class_ai.action._normalize import expand
from director_class_ai.core import (
    DetectorSignal,
    FusionPolicy,
    Locus,
    Plane,
    PlattCalibrator,
    fuse,
)

_prob = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)


def _content(score: float) -> DetectorSignal:
    return DetectorSignal(
        detector="d",
        plane=Plane.CONTENT,
        score=score,
        locus=Locus.RESPONSE,
        signal_type="t",
    )


class TestFusionInvariants:
    @given(st.lists(_prob, min_size=0, max_size=8))
    def test_risk_is_bounded(self, scores: list[float]) -> None:
        v = fuse([_content(s) for s in scores])
        assert 0.0 <= v.risk <= 1.0
        for r in v.plane_risk.values():
            assert 0.0 <= r <= 1.0

    @given(st.lists(_prob, min_size=1, max_size=6), _prob)
    def test_adding_a_signal_never_lowers_content_risk(
        self, scores: list[float], extra: float
    ) -> None:
        # noisy-OR is monotone non-decreasing in the number of signals
        base = FusionPolicy().content_risk([_content(s) for s in scores])
        more = FusionPolicy().content_risk([_content(s) for s in [*scores, extra]])
        assert more >= base - 1e-9


class TestCalibrationInvariants:
    @given(st.floats(-5, 5), st.floats(-5, 5), _prob)
    def test_calibrated_score_is_a_probability(
        self, a: float, b: float, raw: float
    ) -> None:
        assert 0.0 <= PlattCalibrator(a=a, b=b).calibrate(raw) <= 1.0

    @given(st.floats(0.01, 5), st.floats(-5, 5), _prob, _prob)
    def test_monotone_in_raw_for_positive_slope(
        self, a: float, b: float, lo: float, hi: float
    ) -> None:
        cal = PlattCalibrator(a=a, b=b)
        x, y = sorted((lo, hi))
        assert cal.calibrate(x) <= cal.calibrate(y) + 1e-12


class TestNormalizeInvariants:
    @given(st.text(max_size=120))
    def test_expand_keeps_original_and_is_bounded(self, command: str) -> None:
        forms = expand(command)
        assert len(forms) <= 64
        assert all(f.strip() for f in forms)  # never emits a blank form
        if command.strip():
            assert command.strip() in forms or command in forms
