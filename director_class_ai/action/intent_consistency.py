# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — intent-consistency detector (action plane, tier 0)

"""Flag actions that do not match the task the agent was given.

An agent asked to "summarise the quarterly report" has no business running
``DROP TABLE`` — a mutating or destructive action under a read-only task is a sign
the agent pivoted (a reasoning failure, a hijack, or an injected instruction). This
tier-0 heuristic compares the task's intent with the action: when the task asks
only to read / understand and the action changes state, it fires, scaled by how
destructive the action is. When the user explicitly asked to change something the
mutation is expected, so it stays silent. A semantic NLI version (task ⊨ action)
lives in the model-backed detectors extra; this cheap check runs on every call.
"""

from __future__ import annotations

from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)
from ._lexicon import IRREVERSIBLE, MUTATING, MUTATING_TASK, READ_ONLY_TASK

__all__ = ["IntentConsistencyDetector"]


class IntentConsistencyDetector:
    """Tier-0 action-plane detector for action/task intent mismatch."""

    name = "intent_consistency"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        command = (request.action or "").strip()
        task = (request.query or "").strip()
        if not command or not task:
            return None
        if not MUTATING.search(command):
            return None  # read-only action never conflicts with the task
        # The user explicitly authorised a change → mutation is expected.
        if MUTATING_TASK.search(task):
            return None
        # Action mutates but the task is purely read-only → the agent pivoted.
        if not READ_ONLY_TASK.search(task):
            return None  # task intent is unclear; do not guess
        if IRREVERSIBLE.search(command):
            score, severity = 0.8, Severity.HIGH
        else:
            score, severity = 0.6, Severity.MEDIUM
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=score,
            locus=Locus.ACTION,
            signal_type="intent_mismatch",
            severity=severity,
            rationale="state-changing action under a read-only task",
        )
