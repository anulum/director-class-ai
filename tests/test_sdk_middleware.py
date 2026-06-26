# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — Python SDK middleware tests

from __future__ import annotations

from pathlib import Path

import pytest

from director_class_ai.approvals import ApprovalQueue
from director_class_ai.audit import verify_chain
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)
from director_class_ai.sdk import (
    ToolExecutionResult,
    ToolMiddlewareDecision,
    ToolReviewMiddleware,
    ToolReviewRequest,
)


class _BorderlineAction:
    """Action detector that routes a request to human approval."""

    name = "borderline_action"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Return a borderline signal for approval-route tests."""
        if "maybe" not in request.action:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=0.2,
            locus=Locus.ACTION,
            signal_type="borderline_tool",
            severity=Severity.MEDIUM,
        )


class _ExecutorSpy:
    """Records requests that reach the injected executor."""

    def __init__(self) -> None:
        self.calls: list[ToolReviewRequest] = []

    def __call__(self, request: ToolReviewRequest) -> ToolExecutionResult:
        self.calls.append(request)
        return ToolExecutionResult({"status": "ok"}, exit_code=0)


def test_rendered_action_uses_explicit_action_when_supplied() -> None:
    request = ToolReviewRequest(
        tool_name="shell.run",
        arguments={"command": "ignored"},
        action="ls -la",
    )

    assert request.rendered_action() == "ls -la"


def test_rendered_action_is_stable_for_argument_order() -> None:
    left = ToolReviewRequest("tool", {"b": 2, "a": 1})
    right = ToolReviewRequest("tool", {"a": 1, "b": 2})

    assert left.rendered_action() == right.rendered_action()
    assert left.rendered_action().splitlines() == ["tool", "a=1", "b=2"]


def test_to_evaluation_preserves_review_metadata() -> None:
    request = ToolReviewRequest(
        tool_name="fs.read",
        arguments={"path": "README.md"},
        argument_provenance={"path": "user"},
        provenance="user",
        query="read the file",
        tenant_id="tenant-a",
        metadata={"trace_id": "trace-a"},
    )

    evaluation = request.to_evaluation()

    assert evaluation.action == 'fs.read\npath="README.md"'
    assert evaluation.action_provenance == "user"
    assert evaluation.tenant_id == "tenant-a"
    assert evaluation.metadata["tool_name"] == "fs.read"
    assert evaluation.metadata["argument_keys"] == ("path",)
    assert evaluation.metadata["argument_provenance"] == {"path": "user"}
    assert evaluation.metadata["trace_id"] == "trace-a"


def test_review_allows_safe_tool_without_execution() -> None:
    request = ToolReviewRequest("fs.read", {"path": "README.md"}, provenance="user")

    decision = ToolReviewMiddleware.default().review(request)

    assert decision.route == "allow"
    assert decision.permitted is True
    assert decision.executed is False
    assert decision.output_digest == ""


def test_dry_run_default_does_not_execute_safe_tool() -> None:
    spy = _ExecutorSpy()
    request = ToolReviewRequest("fs.read", {"path": "README.md"}, provenance="user")

    decision = ToolReviewMiddleware.default(executor=spy).run(request)

    assert decision.route == "allow"
    assert decision.executed is False
    assert spy.calls == []


def test_permitted_non_dry_run_executes_once() -> None:
    spy = _ExecutorSpy()
    request = ToolReviewRequest(
        "fs.read",
        {"path": "README.md"},
        provenance="user",
        dry_run=False,
    )

    decision = ToolReviewMiddleware.default(executor=spy).run(request)

    assert decision.route == "allow"
    assert decision.executed is True
    assert decision.output_digest
    assert decision.output_size > 0
    assert decision.exit_code == 0
    assert spy.calls == [request]


def test_blocked_tool_never_executes() -> None:
    spy = _ExecutorSpy()
    request = ToolReviewRequest(
        "shell.run",
        {"command": "rm -rf /"},
        action="rm -rf /",
        provenance="user",
        dry_run=False,
    )

    decision = ToolReviewMiddleware.default(executor=spy).run(request)

    assert decision.route == "human"
    assert decision.permitted is False
    assert decision.executed is False
    assert "destructive_command" in decision.firing
    assert spy.calls == []


def test_untrusted_mutating_tool_never_downgrades_to_approval() -> None:
    spy = _ExecutorSpy()
    request = ToolReviewRequest(
        "deploy.update",
        {"target": "production"},
        action="deploy production",
        provenance="retrieved",
        dry_run=False,
    )

    decision = ToolReviewMiddleware.default(executor=spy).run(request)

    assert decision.route == "block"
    assert decision.executed is False
    assert "origin_taint" in decision.firing
    assert spy.calls == []


def test_human_route_requires_approval_before_execution() -> None:
    spy = _ExecutorSpy()
    request = ToolReviewRequest("ops.maybe", action="maybe risky op", dry_run=False)
    middleware = ToolReviewMiddleware.default(
        detectors=(_BorderlineAction(),),
        executor=spy,
    )

    decision = middleware.run(request)

    assert decision.route == "human"
    assert decision.permitted is False
    assert decision.executed is False
    assert spy.calls == []


def test_approved_human_route_executes_once() -> None:
    spy = _ExecutorSpy()
    request = ToolReviewRequest("ops.maybe", action="maybe risky op", dry_run=False)
    middleware = ToolReviewMiddleware.default(
        detectors=(_BorderlineAction(),),
        approval=lambda _verdict, _request: True,
        executor=spy,
    )

    decision = middleware.run(request)

    assert decision.route == "human"
    assert decision.permitted is True
    assert decision.executed is True
    assert spy.calls == [request]


def test_default_wires_durable_approval_and_audit_paths(tmp_path: Path) -> None:
    spy = _ExecutorSpy()
    audit_log = tmp_path / "sdk-audit.jsonl"
    approval_store = tmp_path / "sdk-approvals.json"
    request = ToolReviewRequest("ops.maybe", action="maybe risky op", dry_run=False)

    first = ToolReviewMiddleware.default(
        detectors=(_BorderlineAction(),),
        approval_store=approval_store,
        audit_log=audit_log,
        policy_profile="sdk-production",
        executor=spy,
    ).run(request)

    assert first.route == "human"
    assert first.permitted is False
    assert first.executed is False
    ticket = ApprovalQueue(approval_store).get(first.request_digest)
    assert ticket is not None
    assert ticket.status == "pending"
    assert verify_chain(audit_log).ok
    first_entry = audit_log.read_text(encoding="utf-8").splitlines()[0]
    assert '"policy_profile": "sdk-production"' in first_entry

    ApprovalQueue(approval_store).approve(first.request_digest, approver="alice")
    second = ToolReviewMiddleware.default(
        detectors=(_BorderlineAction(),),
        approval_store=approval_store,
        audit_log=audit_log,
        executor=spy,
    ).run(request)

    assert second.route == "human"
    assert second.permitted is True
    assert second.executed is True
    assert spy.calls == [request]
    assert verify_chain(audit_log).ok
    assert len(audit_log.read_text(encoding="utf-8").splitlines()) == 2


def test_default_rejects_duplicate_approval_sources(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="approval or approval_store"):
        ToolReviewMiddleware.default(
            approval=lambda _verdict, _request: True,
            approval_store=tmp_path / "approvals.json",
        )


def test_default_rejects_duplicate_audit_sources(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="audit_sink or audit_log"):
        ToolReviewMiddleware.default(
            audit_sink=lambda _record: None,
            audit_log=tmp_path / "audit.jsonl",
        )


def test_per_call_executor_overrides_constructor_executor() -> None:
    default_spy = _ExecutorSpy()
    override_spy = _ExecutorSpy()
    request = ToolReviewRequest("fs.read", dry_run=False)

    decision = ToolReviewMiddleware.default(executor=default_spy).run(
        request,
        executor=override_spy,
    )

    assert decision.executed is True
    assert default_spy.calls == []
    assert override_spy.calls == [request]


def test_audit_event_is_digest_only_and_key_based() -> None:
    request = ToolReviewRequest(
        "fs.write",
        {"path": "private.txt", "data": "raw-value-not-for-audit"},
        argument_provenance={"path": "user", "data": "retrieved"},
        metadata={"trace_id": "trace-a"},
        provenance="user",
    )

    event = ToolReviewMiddleware.default().review(request).to_audit_event()

    assert event["event_type"] == "tool_middleware_decision"
    assert event["argument_keys"] == ("data", "path")
    assert event["tainted_argument_keys"] == ("data",)
    assert event["metadata_keys"] == ("trace_id",)
    assert event["action_digest"]
    assert "raw-value-not-for-audit" not in repr(event)
    assert "private.txt" not in repr(event)


def test_decision_factory_marks_execution_absent() -> None:
    request = ToolReviewRequest("fs.read")
    decision = ToolReviewMiddleware.default().review(request)

    rebuilt = ToolMiddlewareDecision.from_governor(request, decision.decision)

    assert rebuilt.executed is False
    assert rebuilt.output_size == 0
