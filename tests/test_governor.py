# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — effector-boundary governor tests

from __future__ import annotations

from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Governor,
    Locus,
    ParallelEnsembleScorer,
    Plane,
)


class _BorderlineContent:
    """Emits a content signal at 0.4 (below 0.5, inside the band) for any response."""

    name = "borderline"
    plane = Plane.CONTENT
    tier = 1

    def evaluate(self, request: EvaluationRequest):
        if not request.response.strip():
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.CONTENT,
            score=0.4,
            locus=Locus.RESPONSE,
            signal_type="borderline",
        )


def _governor(**kw) -> Governor:
    ensemble = ParallelEnsembleScorer(
        [DestructiveCommandDetector(), _BorderlineContent()]
    )
    return Governor(ensemble=ensemble, **kw)


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
    assert first.request_digest and len(first.request_digest) == 16
    # the digest must not leak the raw command
    assert "rm -rf" not in first.request_digest


def test_audit_sink_is_called() -> None:
    seen = []
    gov = _governor(audit_sink=seen.append)
    gov.review(EvaluationRequest(action="rm -rf /"))
    assert len(seen) == 1 and seen[0].permitted is False


def test_digest_is_stable_for_same_request() -> None:
    gov = _governor()
    a = gov.review(EvaluationRequest(action="rm -rf /tmp/x")).record.request_digest
    b = gov.review(EvaluationRequest(action="rm -rf /tmp/x")).record.request_digest
    assert a == b
