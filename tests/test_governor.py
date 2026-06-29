# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — effector-boundary governor tests

from __future__ import annotations

import pytest

from director_class_ai.action import DestructiveCommandDetector, OriginTaintDetector
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Governor,
    Locus,
    ParallelEnsembleScorer,
    Plane,
)
from director_class_ai.core.fusion import Verdict
from director_class_ai.core.governor import (
    ApprovalHook,
    AuditRecord,
    AuditSink,
    digest_request,
)


class _BorderlineContent:
    """Emits a content signal at 0.4 (below 0.5, inside the band) for any response."""

    name = "borderline"
    plane = Plane.CONTENT
    tier = 1

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        if not request.response.strip():
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.CONTENT,
            score=0.4,
            locus=Locus.RESPONSE,
            signal_type="borderline",
        )


def _governor(
    *,
    approval: ApprovalHook | None = None,
    audit_sink: AuditSink | None = None,
) -> Governor:
    ensemble = ParallelEnsembleScorer(
        [DestructiveCommandDetector(), _BorderlineContent()]
    )
    return Governor(ensemble=ensemble, approval=approval, audit_sink=audit_sink)


def test_safe_request_is_permitted() -> None:
    d = _governor().review(EvaluationRequest(action="ls -la"))
    assert d.permitted is True and d.escalated is False


def test_destructive_action_is_blocked() -> None:
    d = _governor().review(EvaluationRequest(action="rm -rf /"))
    assert d.permitted is False
    assert "destructive_command" in d.record.firing


def test_escalation_without_approver_stays_blocked() -> None:
    # borderline content -> requires_human, allow stays True -> escalate, but no
    # approver means fail-closed: not permitted
    d = _governor().review(EvaluationRequest(response="borderline answer"))
    assert d.escalated is True
    assert d.permitted is False


def test_escalation_approved_is_permitted() -> None:
    d = _governor(approval=lambda _v, _r: True).review(
        EvaluationRequest(response="borderline answer")
    )
    assert d.escalated is True and d.permitted is True


def test_escalation_denied_is_blocked() -> None:
    d = _governor(approval=lambda _v, _r: False).review(
        EvaluationRequest(response="borderline answer")
    )
    assert d.escalated is True and d.permitted is False


def test_audit_record_and_trail() -> None:
    gov = _governor()
    gov.review(EvaluationRequest(action="rm -rf /"))
    gov.review(EvaluationRequest(action="ls"))
    assert len(gov.trail) == 2
    first = gov.trail[0]
    assert first.permitted is False
    assert first.request_digest and len(first.request_digest) == 64
    # the digest must not leak the raw command
    assert "rm -rf" not in first.request_digest


def test_audit_sink_is_called() -> None:
    seen: list[AuditRecord] = []
    gov = _governor(audit_sink=seen.append)
    gov.review(EvaluationRequest(action="rm -rf /"))
    assert len(seen) == 1 and seen[0].permitted is False


def test_digest_is_stable_for_same_request() -> None:
    gov = _governor()
    a = gov.review(EvaluationRequest(action="rm -rf /tmp/x")).record.request_digest
    b = gov.review(EvaluationRequest(action="rm -rf /tmp/x")).record.request_digest
    assert a == b


def test_digest_binds_tenant_id() -> None:
    first = digest_request(EvaluationRequest(action="rm -rf /tmp/x", tenant_id="a"))
    second = digest_request(EvaluationRequest(action="rm -rf /tmp/x", tenant_id="b"))

    assert first != second
    assert len(first) == len(second) == 64


def test_digest_binds_deployment_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    request = EvaluationRequest(action="rm -rf /tmp/x", tenant_id="tenant")
    monkeypatch.setenv("DIRECTOR_CLASS_DIGEST_SALT", "deployment-a")
    first = digest_request(request)
    monkeypatch.setenv("DIRECTOR_CLASS_DIGEST_SALT", "deployment-b")
    second = digest_request(request)

    assert first != second
    assert len(first) == len(second) == 64


def _action_governor(
    *,
    approval: ApprovalHook | None = None,
    audit_sink: AuditSink | None = None,
) -> Governor:
    ensemble = ParallelEnsembleScorer(
        [DestructiveCommandDetector(), OriginTaintDetector()]
    )
    return Governor(ensemble=ensemble, approval=approval, audit_sink=audit_sink)


_USER_PERMISSION_CHANGE = EvaluationRequest(
    action="chmod -R 777 /srv",
    query="make /srv writable for the migration window",
    action_provenance="user",
)

_USER_DROP = EvaluationRequest(
    action="DROP TABLE staging_import;",
    query="drop the staging_import table",
    action_provenance="user",
)


def test_user_authorised_destructive_escalates_not_hard_blocks() -> None:
    d = _action_governor().review(_USER_PERMISSION_CHANGE)
    # No approver: fail-closed, so still not permitted — but escalated, not a dead
    # hard block. The audit record carries the human-review flag.
    assert d.escalated is True
    assert d.permitted is False
    assert d.record.requires_human is True
    assert "permission_wipe" in d.record.firing


def test_user_authorised_destructive_proceeds_once_approved() -> None:
    d = _action_governor(approval=lambda _v, _r: True).review(_USER_PERMISSION_CHANGE)
    assert d.escalated is True and d.permitted is True


def test_irreversible_user_destructive_hard_blocks_without_approval() -> None:
    consulted: list[int] = []

    def _approve(_v: Verdict, _r: EvaluationRequest) -> bool:
        consulted.append(1)
        return True

    d = _action_governor(approval=_approve).review(_USER_DROP)
    assert d.escalated is False
    assert d.permitted is False
    assert d.record.requires_human is False
    assert "sql_drop" in d.record.firing
    assert not consulted


def test_injected_destructive_hard_blocks_never_escalates() -> None:
    # Same DROP, but sourced from retrieved content (injection): origin taint fires,
    # so it is a hard block — an approver is never even consulted.
    consulted: list[int] = []

    def _approve(_v: Verdict, _r: EvaluationRequest) -> bool:
        consulted.append(1)
        return True

    d = _action_governor(approval=_approve).review(
        EvaluationRequest(
            action="DROP TABLE audit_log;",
            query="report the row counts",
            action_provenance="retrieved",
        )
    )
    assert d.permitted is False
    assert d.escalated is False
    assert not consulted, "a hard block must not consult the approver"
