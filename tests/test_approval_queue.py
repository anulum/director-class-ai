# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval queue + policy tests

from __future__ import annotations

import pytest

from director_class_ai.approvals import ApprovalPolicy, ApprovalQueue
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
    Verdict,
)
from director_class_ai.core.governor import digest_request


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _req(action: str = "maybe risky") -> EvaluationRequest:
    return EvaluationRequest(action=action)


def _digest(action: str = "maybe risky") -> str:
    return digest_request(_req(action))


class TestApprovalQueue:
    def test_first_request_escalates_and_creates_pending(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        assert q.request_approval(None, _req()) is False
        pend = q.pending()
        assert len(pend) == 1 and pend[0].status == "pending"

    def test_approve_then_consume_once(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req())
        q.approve(_digest(), approver="alice")
        assert q.request_approval(None, _req()) is True  # consumed
        # single use: the same approval cannot permit a second execution
        assert q.request_approval(None, _req()) is False

    def test_repeated_request_keeps_single_pending(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        assert q.request_approval(None, _req()) is False
        assert q.request_approval(None, _req()) is False  # existing pending reused
        assert len(q.pending()) == 1

    def test_denied_stays_blocked(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req())
        q.deny(_digest(), approver="alice")
        assert q.request_approval(None, _req()) is False

    def test_no_cross_digest_reuse(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req("maybe A"))
        q.approve(_digest("maybe A"), approver="alice")
        # an approval for action A must not permit a different action B
        assert q.request_approval(None, _req("maybe B")) is False

    def test_expiry_invalidates_approval(self, tmp_path) -> None:
        clock = _Clock()
        q = ApprovalQueue(tmp_path / "q.json", clock=clock, ttl_seconds=10.0)
        q.request_approval(None, _req())
        q.approve(_digest(), approver="alice")
        clock.t += 11.0  # past TTL
        assert q.request_approval(None, _req()) is False  # expired -> re-pending

    def test_approve_unknown_raises(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        with pytest.raises(KeyError):
            q.approve("deadbeef", approver="x")

    def test_decide_non_pending_raises(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req())
        q.approve(_digest(), approver="alice")
        with pytest.raises(ValueError, match="not pending"):
            q.approve(_digest(), approver="bob")

    def test_persistence_across_instances(self, tmp_path) -> None:
        p = tmp_path / "q.json"
        ApprovalQueue(p).request_approval(None, _req())
        ApprovalQueue(p).approve(_digest(), approver="alice")  # fresh instance
        assert ApprovalQueue(p).request_approval(None, _req()) is True

    def test_get_returns_ticket(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req())
        t = q.get(_digest())
        assert t is not None and t.digest == _digest()
        assert q.get("nope") is None


def _sig(sev: Severity) -> DetectorSignal:
    return DetectorSignal(
        detector="d",
        plane=Plane.ACTION,
        score=0.9,
        locus=Locus.ACTION,
        signal_type="t",
        severity=sev,
    )


class TestApprovalPolicy:
    def test_critical_routes_to_dual_human(self) -> None:
        v = Verdict(False, 0.9, True, firing=(_sig(Severity.CRITICAL),))
        assert ApprovalPolicy().route(v) == "dual_human"

    def test_high_routes_to_human(self) -> None:
        v = Verdict(False, 0.9, True, firing=(_sig(Severity.HIGH),))
        assert ApprovalPolicy().route(v) == "human"

    def test_no_firing_uses_default(self) -> None:
        v = Verdict(True, 0.1, False, firing=())
        assert ApprovalPolicy().route(v) == "auto"

    def test_unmapped_severity_uses_default(self) -> None:
        v = Verdict(True, 0.1, True, firing=(_sig(Severity.LOW),))
        assert ApprovalPolicy().route(v) == "auto"
