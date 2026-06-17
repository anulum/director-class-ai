# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — semantic action-support detector (action plane, tier 1)

"""Measure whether the task the agent was given *supports* the action it proposes.

This is the model-backed maturation of the tier-0 ``IntentConsistencyDetector``.
The heuristic compares verb lexicons — it catches "summarise the report" → ``DROP
TABLE`` but not "delete file A" → "delete the whole database", because both look
like authorised mutations to a keyword matcher. This detector asks an entailment
model instead: with the task as the premise and the proposed action as the
hypothesis, a low entailment (high divergence) means the action is *not supported*
by what the user asked — a pivot, a hijack, or an injected instruction.

It runs at tier 1 (model-backed) only on state-changing actions, so the cheap
tier-0 detectors clear read-only traffic first and the model is spent on the
mutations that actually matter. The entailment scorer is injected, so the boundary
logic is unit-tested without loading a model; ``from_pretrained`` wires
director-ai's NLI scorer, whose :meth:`score` returns logical divergence in
``[0, 1]`` (0 = the task entails the action, 1 = they diverge).

The threshold is a deliberate, documented default; the *measured* operating point
belongs to the action-corpus evaluation (a labelled task/action set) and is not
claimed until that corpus reaches the claim-grade bar.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..action._lexicon import IRREVERSIBLE, MUTATING, MUTATING_TASK
from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)

__all__ = ["SemanticActionSupportDetector", "SupportScorer"]


@runtime_checkable
class SupportScorer(Protocol):
    """An entailment scorer: ``score(premise, hypothesis)`` divergence in [0, 1]."""

    def score(self, premise: str, hypothesis: str) -> float:
        """Return task/action divergence in [0, 1]."""
        ...


class SemanticActionSupportDetector:
    """Tier-1 action-plane detector: is the action entailed by the task?"""

    name = "semantic_action_support"
    plane = Plane.ACTION
    tier = 1  # model-backed: runs after the cheap tier-0 action detectors

    def __init__(self, scorer: SupportScorer, *, threshold: float = 0.6) -> None:
        self._scorer = scorer
        self._threshold = float(threshold)

    @classmethod
    def from_pretrained(
        cls, *, threshold: float = 0.6, **kwargs: Any
    ) -> SemanticActionSupportDetector:  # pragma: no cover - needs [detectors] extra
        """Load the optional director-ai NLI scorer for task/action support."""
        from director_ai.core.scoring.nli import NLIScorer

        return cls(NLIScorer(**kwargs), threshold=threshold)

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Emit a signal when a mutating action is unsupported by the task."""
        task = (request.query or "").strip()
        action = (request.action or "").strip()
        if not task or not action:
            return None
        # Only state-changing actions can be an unsupported pivot; a read needs no
        # task authorisation and is covered by the origin-taint / blast detectors.
        if not MUTATING.search(action):
            return None
        divergence = float(self._scorer.score(task, _hypothesis(action)))
        if divergence < self._threshold:
            return None
        irreversible = bool(IRREVERSIBLE.search(action))
        authorised = bool(MUTATING_TASK.search(task))
        # An irreversible action the task never authorised is the worst case.
        worst = irreversible and not authorised
        severity = Severity.HIGH if worst else Severity.MEDIUM
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=divergence,
            locus=Locus.ACTION,
            signal_type="action_not_supported",
            severity=severity,
            rationale=(
                f"task does not entail the proposed action (divergence {divergence:.2f})"
            ),
        )


def _hypothesis(action: str) -> str:
    """Render an action as an NLI hypothesis the task premise can entail or not."""
    return f"The user asked for this action: {action}"
