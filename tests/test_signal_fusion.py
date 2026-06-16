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


def sig(
    plane,
    score,
    *,
    sev=Severity.MEDIUM,
    calib=1.0,
    locus=Locus.RESPONSE,
    name="d",
    stype="t",
):
    return DetectorSignal(
        detector=name,
        plane=plane,
        score=score,
        locus=locus,
        signal_type=stype,
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


class TestAuthorisedDestructiveRouting:
    """A user-originated, taint-free destructive op escalates instead of hard-blocking.

    The whole point is recoverability: a hard block on an op the user explicitly
    asked for is a dead end, so it is routed to a human approval gate — but only
    when the origin is the user and no injection / exfiltration / taint signal
    fired. Every other path keeps the fail-closed hard block.
    """

    def _destructive(self, *, sev=Severity.HIGH, stype="history_rewrite"):
        return sig(Plane.ACTION, 0.9, sev=sev, locus=Locus.ACTION, stype=stype)

    def test_user_authorised_destructive_escalates_not_blocks(self) -> None:
        v = fuse([self._destructive()], provenance="user")
        assert v.allow is True
        assert v.requires_human is True
        assert "user-authorised" in v.rationale and "escalat" in v.rationale

    def test_critical_user_authorised_also_escalates(self) -> None:
        v = fuse([self._destructive(sev=Severity.CRITICAL, stype="sql_drop")],
                 provenance="user")
        assert v.allow is True
        assert v.requires_human is True

    def test_unknown_provenance_still_hard_blocks(self) -> None:
        # The default empty provenance must stay fail-closed (no silent softening).
        v = fuse([self._destructive()])
        assert v.allow is False
        assert v.requires_human is False

    def test_untrusted_provenance_still_hard_blocks(self) -> None:
        v = fuse([self._destructive()], provenance="retrieved")
        assert v.allow is False

    def test_user_origin_with_taint_signal_still_blocks(self) -> None:
        # provenance says "user" but a taint-class objector fired (e.g. a tainted
        # MCP argument): the danger is injection, not an authorised op → hard block.
        objectors = [
            self._destructive(sev=Severity.CRITICAL, stype="sql_drop"),
            sig(Plane.ACTION, 0.85, sev=Severity.HIGH, locus=Locus.ACTION,
                stype="mcp_tool_call"),
        ]
        v = fuse(objectors, provenance="user")
        assert v.allow is False

    def test_exfiltration_signal_never_authorised(self) -> None:
        v = fuse(
            [sig(Plane.ACTION, 0.9, sev=Severity.HIGH, locus=Locus.ACTION,
                 stype="exfiltration")],
            provenance="user",
        )
        assert v.allow is False

    def test_content_block_is_not_resurrected_by_action_escalation(self) -> None:
        # A content objection that already blocked must win — softening the action
        # verdict to escalation does not allow the request through.
        v = fuse(
            [sig(Plane.CONTENT, 0.9), self._destructive()],
            provenance="user",
        )
        assert v.allow is False
        assert v.requires_human is True

    def test_provenance_match_is_case_insensitive(self) -> None:
        v = fuse([self._destructive()], provenance="  USER ")
        assert v.allow is True and v.requires_human is True

    def test_taint_set_is_policy_tunable(self) -> None:
        # Treat history_rewrite as taint-class via policy → it can no longer be
        # authorised, so it hard-blocks even from the user.
        policy = FusionPolicy(taint_signal_types=frozenset({"history_rewrite"}))
        v = fuse([self._destructive()], policy, provenance="user")
        assert v.allow is False


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


class TestUncertaintyEscalation:
    def test_content_borderline_allows_but_flags_for_review(self) -> None:
        # risk 0.42 is below 0.5 but within the 0.15 band -> allow + requires_human
        v = fuse([sig(Plane.CONTENT, 0.42)])
        assert v.allow is True
        assert v.requires_human is True
        assert "borderline" in v.rationale

    def test_action_borderline_escalates(self) -> None:
        # action risk 0.2 is below the 0.3 block threshold but within the band
        v = fuse([sig(Plane.ACTION, 0.2, locus=Locus.ACTION)])
        assert v.allow is True
        assert v.requires_human is True

    def test_confidently_safe_not_escalated(self) -> None:
        v = fuse([sig(Plane.CONTENT, 0.1)])
        assert v.allow is True and v.requires_human is False

    def test_margin_zero_disables_borderline(self) -> None:
        policy = FusionPolicy(uncertainty_margin=0.0)
        v = fuse([sig(Plane.CONTENT, 0.42)], policy)
        assert v.requires_human is False

    def test_split_panel_lands_in_band(self) -> None:
        # a split panel produces a mid-range fused risk that lands in the band,
        # which is exactly when a human should review it
        v = fuse([sig(Plane.CONTENT, 0.4)])
        assert v.allow is True and v.requires_human is True
