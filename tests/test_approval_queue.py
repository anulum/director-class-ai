# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval queue + policy tests

from __future__ import annotations

import json

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

    def test_critical_verdict_requires_two_distinct_approvers(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        verdict = Verdict(False, 0.97, True, firing=(_sig(Severity.CRITICAL),))
        assert q.request_approval(verdict, _req()) is False

        first = q.approve(_digest(), approver="alice")
        assert first.status == "pending"
        assert first.required_approvals == 2
        assert q.request_approval(verdict, _req()) is False

        second = q.approve(_digest(), approver="bob")
        assert second.status == "approved"
        assert second.approvers == ("alice", "bob")
        assert q.request_approval(verdict, _req()) is True

    def test_same_approver_cannot_satisfy_dual_approval(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        verdict = Verdict(False, 0.97, True, firing=(_sig(Severity.CRITICAL),))
        q.request_approval(verdict, _req())
        q.approve(_digest(), approver="alice")

        with pytest.raises(ValueError, match="already approved"):
            q.approve(_digest(), approver="alice")

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

    def test_failed_atomic_replace_preserves_existing_queue(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        p = tmp_path / "q.json"
        q = ApprovalQueue(p)
        q.request_approval(None, _req("maybe A"))
        before = p.read_text(encoding="utf-8")

        def _fail_replace(_source: object, _target: object) -> None:
            raise OSError("simulated crash during queue replacement")

        monkeypatch.setattr("director_class_ai.core.durability.os.replace", _fail_replace)
        with pytest.raises(OSError, match="simulated crash"):
            q.request_approval(None, _req("maybe B"))

        assert p.read_text(encoding="utf-8") == before
        reloaded = ApprovalQueue(p)
        ticket = reloaded.get(_digest("maybe A"))
        assert ticket is not None
        assert ticket.status == "pending"
        assert reloaded.get(_digest("maybe B")) is None

    def test_get_returns_ticket(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req())
        t = q.get(_digest())
        assert t is not None and t.digest == _digest()
        assert q.get("nope") is None

    def test_rejects_corrupt_queue_document(self, tmp_path) -> None:
        path = tmp_path / "q.json"
        path.write_text("[]", encoding="utf-8")

        with pytest.raises(ValueError, match="JSON object"):
            ApprovalQueue(path).pending()

    def test_rejects_corrupt_queue_entry(self, tmp_path) -> None:
        path = tmp_path / "q.json"
        path.write_text(json.dumps({"digest": "not-a-ticket"}), encoding="utf-8")

        with pytest.raises(ValueError, match="ticket objects"):
            ApprovalQueue(path).pending()

    def test_legacy_single_approver_is_migrated(self, tmp_path) -> None:
        path = tmp_path / "q.json"
        digest = _digest()
        path.write_text(
            json.dumps(
                {
                    digest: {
                        "digest": digest,
                        "status": "approved",
                        "created_at": 1,
                        "decided_at": 2,
                        "approver": "alice",
                        "approvers": [],
                        "required_approvals": 1,
                    }
                }
            ),
            encoding="utf-8",
        )

        ticket = ApprovalQueue(path).get(digest)

        assert ticket is not None
        assert ticket.approvers == ("alice",)

    def test_pending_ticket_required_approvals_can_increase(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req())
        verdict = Verdict(False, 0.97, True, firing=(_sig(Severity.CRITICAL),))

        assert q.request_approval(verdict, _req()) is False

        ticket = q.get(_digest())
        assert ticket is not None
        assert ticket.required_approvals == 2

    def test_blank_approver_is_rejected(self, tmp_path) -> None:
        q = ApprovalQueue(tmp_path / "q.json")
        q.request_approval(None, _req())

        with pytest.raises(ValueError, match="approver is required"):
            q.approve(_digest(), approver="  ")

    def test_invalid_required_approvals_defaults_to_one(self, tmp_path) -> None:
        path = tmp_path / "q.json"
        digest = _digest()
        path.write_text(
            json.dumps(
                {
                    digest: {
                        "digest": digest,
                        "status": "pending",
                        "created_at": 1,
                        "required_approvals": 0,
                    }
                }
            ),
            encoding="utf-8",
        )

        ticket = ApprovalQueue(path).get(digest)

        assert ticket is not None
        assert ticket.required_approvals == 1


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
