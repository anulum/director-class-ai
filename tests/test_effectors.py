# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — effector boundary tests

from __future__ import annotations

from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Governor,
    Locus,
    ParallelEnsembleScorer,
    Plane,
    Severity,
)
from director_class_ai.effectors import (
    EffectorKind,
    EffectorRequest,
    ReversibilityMetadata,
    ShellEffectorAdapter,
    SubprocessGuard,
    default_subprocess_runner,
)


class _BorderlineAction:
    """Emits an action signal at 0.2 (below the 0.3 block threshold, in the band)."""

    name = "borderline_action"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest):
        if "maybe" not in request.action:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=0.2,
            locus=Locus.ACTION,
            signal_type="borderline",
            severity=Severity.MEDIUM,
        )


class _Spy:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, command: str) -> tuple[str, int]:
        self.calls.append(command)
        return ("output", 0)


def _adapter(spy: _Spy, *, approval=None) -> ShellEffectorAdapter:
    gov = Governor(
        ensemble=ParallelEnsembleScorer(
            [DestructiveCommandDetector(), _BorderlineAction()]
        ),
        approval=approval,
    )
    return ShellEffectorAdapter(gov, execute=spy)


def test_blocked_action_never_executes() -> None:
    spy = _Spy()
    r = _adapter(spy).run_command("rm -rf /", dry_run=False)
    assert r.permitted is False and r.executed is False
    assert spy.calls == []


def test_escalation_without_approval_never_executes() -> None:
    spy = _Spy()
    r = _adapter(spy).run_command("maybe risky op", dry_run=False)
    assert r.decision.escalated is True
    assert r.permitted is False and r.executed is False
    assert spy.calls == []


def test_approved_escalation_executes_once() -> None:
    spy = _Spy()
    r = _adapter(spy, approval=lambda _v, _r: True).run_command(
        "maybe risky op", dry_run=False
    )
    assert r.permitted is True and r.executed is True
    assert spy.calls == ["maybe risky op"]
    assert r.exit_code == 0 and r.output_digest


def test_safe_dry_run_does_not_execute() -> None:
    spy = _Spy()
    r = _adapter(spy).run_command("ls -la")  # dry_run defaults True
    assert r.permitted is True and r.executed is False
    assert spy.calls == []


def test_safe_real_run_executes() -> None:
    spy = _Spy()
    r = _adapter(spy).run_command("ls -la", dry_run=False)
    assert r.permitted is True and r.executed is True
    assert spy.calls == ["ls -la"]


def test_no_executor_is_dry_run_only() -> None:
    gov = Governor(ensemble=ParallelEnsembleScorer([DestructiveCommandDetector()]))
    r = ShellEffectorAdapter(gov).run_command("ls", dry_run=False)
    assert r.permitted is True and r.executed is False


def test_decision_id_links_to_audit() -> None:
    spy = _Spy()
    r = _adapter(spy).run_command("ls")
    assert r.decision_id == r.decision.record.request_digest


def test_request_to_evaluation_maps_fields() -> None:
    req = EffectorRequest(
        action="rm x", kind=EffectorKind.SHELL, provenance="retrieved", query="q"
    )
    ev = req.to_evaluation()
    assert ev.action == "rm x" and ev.action_provenance == "retrieved" and ev.query == "q"


def test_request_to_evaluation_includes_reversibility_digests_only() -> None:
    metadata = ReversibilityMetadata(
        snapshot_id="snap-1",
        rollback_command="restore snap-1",
        transaction_id="txn-1",
        dry_run_digest="2d711642b726b044",
        diff_digest="9cdb1f24d346aa61",
    )
    req = EffectorRequest(action="rm -rf ./build", reversibility=metadata)
    ev = req.to_evaluation()
    assert ev.metadata["reversibility"] == {
        "snapshot_id": "snap-1",
        "rollback_command": "restore snap-1",
        "transaction_id": "txn-1",
        "dry_run_digest": "2d711642b726b044",
        "diff_digest": "9cdb1f24d346aa61",
    }


def test_shell_run_command_accepts_reversibility_metadata_without_audit_leak() -> None:
    spy = _Spy()
    metadata = ReversibilityMetadata(
        snapshot_id="snap-build",
        rollback_command="restore ./build",
        transaction_id="txn-build",
        dry_run_digest="2d711642b726b044",
        diff_digest="9cdb1f24d346aa61",
    )
    r = _adapter(spy).run_command(
        "rm -rf ./build",
        reversibility=metadata,
        dry_run=False,
    )
    assert r.permitted is True and r.executed is True
    assert "restore ./build" not in r.decision.record.__dict__.values()
    assert r.output_digest


class TestSubprocessGuard:
    def test_dry_run_default_does_not_run(self) -> None:
        spy = _Spy()
        gov = Governor(ensemble=ParallelEnsembleScorer([DestructiveCommandDetector()]))
        r = SubprocessGuard(gov, runner=spy).run("ls")
        assert r.executed is False and spy.calls == []

    def test_blocked_command_not_run(self) -> None:
        spy = _Spy()
        gov = Governor(ensemble=ParallelEnsembleScorer([DestructiveCommandDetector()]))
        r = SubprocessGuard(gov, runner=spy).run("rm -rf /", dry_run=False)
        assert r.permitted is False and spy.calls == []

    def test_default_runner_executes_real_command(self) -> None:
        out, code = default_subprocess_runner("echo guard-probe-123")
        assert "guard-probe-123" in out and code == 0
