# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — Governor + approval queue integration

from __future__ import annotations

from director_class_ai.approvals import ApprovalQueue
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Governor,
    Locus,
    ParallelEnsembleScorer,
    Plane,
    Severity,
)
from director_class_ai.core.governor import digest_request


class _BorderlineAction:
    name = "border"
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
            signal_type="border",
            severity=Severity.MEDIUM,
        )


def test_escalate_then_approve_then_permit(tmp_path) -> None:
    queue = ApprovalQueue(tmp_path / "q.json")
    gov = Governor(
        ensemble=ParallelEnsembleScorer([_BorderlineAction()]),
        approval=queue.request_approval,
    )
    req = EvaluationRequest(action="maybe risky op")

    # 1) first review: escalated, blocked, a pending ticket is opened
    d1 = gov.review(req)
    assert d1.escalated is True and d1.permitted is False
    assert len(queue.pending()) == 1

    # 2) a human approves the exact action
    queue.approve(digest_request(req), approver="alice")

    # 3) re-review: the approval is consumed and the action is permitted
    d2 = gov.review(req)
    assert d2.permitted is True

    # 4) replay protection: the consumed approval does not permit a third time
    d3 = gov.review(req)
    assert d3.permitted is False
