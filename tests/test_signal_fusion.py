# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — signal + fusion tests

from __future__ import annotations

import pytest

from director_class_ai.core import (
    DetectorSignal,
    FusionPolicy,
    Locus,
    Plane,
    Severity,
    fuse,
)


def sig(plane, score, *, sev=Severity.MEDIUM, calib=1.0, locus=Locus.RESPONSE, name="d"):
    return DetectorSignal(
        detector=name,
        plane=plane,
        score=score,
        locus=locus,
        signal_type="t",
        severity=sev,
        calibration=calib,
    )


class TestDetectorSignal:
    def test_score_range_validated(self) -> None:
        with pytest.raises(ValueError, match="score"):
            sig(Plane.CONTENT, 1.5)

    def test_calibration_range_validated(self) -> None:
        with pytest.raises(ValueError, match="calibration"):
            sig(Plane.CONTENT, 0.5, calib=2.0)

    def test_weighted_score_discounts_by_calibration(self) -> None:
        assert sig(Plane.CONTENT, 0.8, calib=0.5).weighted_score == pytest.approx(0.4)


class TestContentFusion:
    def test_below_threshold_allows(self) -> None:
        v = fuse([sig(Plane.CONTENT, 0.2), sig(Plane.CONTENT, 0.1)])
        assert v.allow is True
        assert v.risk < 0.5

    def test_above_threshold_flags(self) -> None:
        v = fuse([sig(Plane.CONTENT, 0.9)])
        assert v.allow is False
        assert v.firing

    def test_noisy_or_combines_weak_agreements(self) -> None:
        # two independent 0.4 signals -> 1 - 0.6*0.6 = 0.64 >= 0.5 -> flagged
        v = fuse([sig(Plane.CONTENT, 0.4), sig(Plane.CONTENT, 0.4)])
        assert v.plane_risk[Plane.CONTENT] == pytest.approx(0.64)
        assert v.allow is False

    def test_calibration_can_keep_below_threshold(self) -> None:
        # a strong raw score from an untrusted detector should not flag alone
        v = fuse([sig(Plane.CONTENT, 0.9, calib=0.3)])
        assert v.plane_risk[Plane.CONTENT] == pytest.approx(0.27)
        assert v.allow is True

    def test_integrity_plane_threshold(self) -> None:
        v = fuse([sig(Plane.INTEGRITY, 0.8)])
        assert v.allow is False
        assert Plane.INTEGRITY in v.plane_risk


class TestActionFusionFailClosed:
    def test_credible_objection_blocks(self) -> None:
        v = fuse([sig(Plane.ACTION, 0.4, locus=Locus.ACTION)])
        assert v.allow is False
        assert v.requires_human is False

    def test_below_block_threshold_allows(self) -> None:
        v = fuse([sig(Plane.ACTION, 0.1, locus=Locus.ACTION)])
        assert v.allow is True

    def test_critical_severity_escalates_to_human(self) -> None:
        v = fuse([sig(Plane.ACTION, 0.95, sev=Severity.CRITICAL, locus=Locus.ACTION)])
        assert v.allow is False
        assert v.requires_human is True
        assert "human" in v.rationale.lower()

    def test_custom_policy_threshold(self) -> None:
        policy = FusionPolicy(action_block_threshold=0.8)
        v = fuse([sig(Plane.ACTION, 0.5, locus=Locus.ACTION)], policy)
        assert v.allow is True  # 0.5 < 0.8 custom block threshold


class TestVerdictShape:
    def test_no_signals_allows(self) -> None:
        v = fuse([])
        assert v.allow is True
        assert v.risk == 0.0
        assert v.rationale == "no detector objected"

    def test_overall_risk_is_max_plane(self) -> None:
        v = fuse(
            [
                sig(Plane.CONTENT, 0.3),
                sig(Plane.ACTION, 0.95, sev=Severity.HIGH, locus=Locus.ACTION),
            ]
        )
        assert v.risk == pytest.approx(0.95)
        assert v.allow is False
