# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy governance workflow tests

from __future__ import annotations

from pathlib import Path

import pytest

from director_class_ai.core.signal import DetectorSignal, Locus, Plane, Severity
from director_class_ai.policy import PolicyGovernance, Profile
from director_class_ai.policy.exposure import ExposureCase


def _profile(threshold: float = 0.3) -> Profile:
    return Profile(
        name="staging", action_block_threshold=threshold, uncertainty_margin=0.0
    )


def _approved_baseline(threshold: float = 0.3) -> PolicyGovernance:
    governance = PolicyGovernance.empty()
    proposal = governance.propose(
        _profile(threshold), proposer="alice", created_at="t0", reason="baseline"
    )
    governance.approve(proposal.digest, reviewer="bob", decided_at="t1")
    return governance


def _action_case(score: float) -> ExposureCase:
    signal = DetectorSignal(
        detector="d",
        plane=Plane.ACTION,
        score=score,
        locus=Locus.ACTION,
        signal_type="destructive_command",
        severity=Severity.HIGH,
    )
    return ExposureCase(label="c", signals=(signal,))


class TestLifecycle:
    def test_empty_has_no_head(self) -> None:
        governance = PolicyGovernance.empty()
        assert governance.head is None
        assert governance.status() == {
            "head_digest": None,
            "head_profile": None,
            "revisions": 0,
            "pending": 0,
        }

    def test_propose_then_approve_sets_head(self) -> None:
        governance = PolicyGovernance.empty()
        proposal = governance.propose(
            _profile(), proposer="alice", created_at="t0", reason="baseline"
        )
        assert governance.pending() == (proposal,)
        revision = governance.approve(proposal.digest, reviewer="bob", decided_at="t1")
        assert governance.head is not None
        assert governance.head.digest == revision.digest
        assert governance.status()["revisions"] == 1
        assert governance.status()["pending"] == 0

    def test_proposal_lookup(self) -> None:
        governance = PolicyGovernance.empty()
        proposal = governance.propose(
            _profile(), proposer="alice", created_at="t0", reason="b"
        )
        assert governance.proposal(proposal.digest) is proposal

    def test_deny_keeps_head_unchanged(self) -> None:
        governance = _approved_baseline()
        head_before = governance.head
        assert head_before is not None
        proposal = governance.propose(
            _profile(0.7), proposer="alice", created_at="t2", reason="relax"
        )
        denied = governance.deny(proposal.digest, reviewer="bob", decided_at="t3")
        assert denied.status == "denied"
        assert governance.head is not None
        assert governance.head.digest == head_before.digest

    def test_rollback_opens_pending_proposal_without_moving_head(self) -> None:
        governance = _approved_baseline(0.3)
        baseline = governance.head
        assert baseline is not None
        proposal = governance.propose(
            _profile(0.7), proposer="alice", created_at="t2", reason="relax"
        )
        relaxed = governance.approve(proposal.digest, reviewer="bob", decided_at="t3")

        rollback = governance.rollback(
            baseline.digest, author="bob", created_at="t4", reason="revert"
        )

        assert rollback.status == "pending"
        assert rollback.revision.parent == relaxed.digest
        assert governance.head is not None
        assert governance.head.digest == relaxed.digest
        restored = governance.approve(rollback.digest, reviewer="carol", decided_at="t5")
        assert restored.digest == baseline.digest
        assert governance.head is not None
        assert governance.head.digest == baseline.digest

    def test_rollback_cannot_be_self_approved(self) -> None:
        governance = _approved_baseline(0.3)
        baseline = governance.head
        assert baseline is not None
        proposal = governance.propose(
            _profile(0.7), proposer="alice", created_at="t2", reason="relax"
        )
        governance.approve(proposal.digest, reviewer="bob", decided_at="t3")
        rollback = governance.rollback(
            baseline.digest, author="bob", created_at="t4", reason="revert"
        )

        with pytest.raises(ValueError, match="cannot be approved by its proposer"):
            governance.approve(rollback.digest, reviewer="bob", decided_at="t5")


class TestExpose:
    def test_expose_reports_decision_delta(self) -> None:
        governance = _approved_baseline(0.3)
        report = governance.expose(_profile(0.7), [_action_case(0.5)])
        assert report.transitions == {"block->allow": 1}

    def test_expose_without_baseline_raises(self) -> None:
        with pytest.raises(ValueError, match="record a baseline first"):
            PolicyGovernance.empty().expose(_profile(0.7), [_action_case(0.5)])


class TestDrift:
    def test_drift_detected_against_head(self) -> None:
        governance = _approved_baseline(0.3)
        event = governance.drift_check(_profile(0.9), detected_at="t9")
        assert event is not None
        assert [c.field for c in event.changes] == ["action_block_threshold"]

    def test_no_drift_when_live_matches_head(self) -> None:
        governance = _approved_baseline(0.3)
        assert governance.drift_check(_profile(0.3), detected_at="t9") is None

    def test_drift_without_baseline_raises(self) -> None:
        with pytest.raises(ValueError, match="no approved posture"):
            PolicyGovernance.empty().drift_check(_profile(), detected_at="t9")


class TestPersistence:
    def test_load_missing_file_starts_empty(self, tmp_path: Path) -> None:
        governance = PolicyGovernance.load(tmp_path / "absent.json")
        assert governance.head is None

    def test_save_then_load_roundtrip(self, tmp_path: Path) -> None:
        store = tmp_path / "gov.json"
        governance = _approved_baseline(0.3)
        pending = governance.propose(
            _profile(0.7), proposer="alice", created_at="t2", reason="relax"
        )
        governance.save(store)

        reloaded = PolicyGovernance.load(store)
        reloaded_head = reloaded.head
        governance_head = governance.head
        assert reloaded_head is not None
        assert governance_head is not None
        assert reloaded_head.digest == governance_head.digest
        assert reloaded.pending()[0].digest == pending.digest
