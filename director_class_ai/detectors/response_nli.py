# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — response-level NLI content adapter

"""Response-level entailment adapter for grounded content decisions.

Token-span detection identifies unsupported phrases and contradiction scoring
targets direct conflicts. This adapter covers the coarser but operationally
important question: does the grounding context entail the response as a whole?
It uses an injected scorer returning logical divergence in ``[0, 1]`` where
``0`` means entailed and ``1`` means divergent, matching the existing
``SemanticActionSupportDetector`` contract.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane, Severity

__all__ = ["ResponseNLIDetector", "ResponseNLIScorer"]


@runtime_checkable
class ResponseNLIScorer(Protocol):
    """A response entailment scorer: divergence in ``[0, 1]``."""

    def score(self, premise: str, hypothesis: str) -> float:
        """Return context/response divergence in ``[0, 1]``."""
        ...


class ResponseNLIDetector:
    """Tier-1 content-plane detector for response-level NLI divergence."""

    name = "response_nli"
    plane = Plane.CONTENT
    tier = 1

    def __init__(self, scorer: ResponseNLIScorer, *, threshold: float = 0.55) -> None:
        self._scorer = scorer
        self._threshold = float(threshold)

    @classmethod
    def from_pretrained(
        cls, *, threshold: float = 0.55, **kwargs: Any
    ) -> ResponseNLIDetector:  # pragma: no cover - needs [detectors] extra
        """Load the optional director-ai NLI scorer for response support."""
        from director_ai.core.scoring.nli import NLIScorer

        return cls(NLIScorer(**kwargs), threshold=threshold)

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Emit a content signal when context does not entail the response."""
        context = request.context.strip()
        response = request.response.strip()
        if not context or not response:
            return None
        divergence = float(self._scorer.score(context, response))
        if divergence < self._threshold:
            return None
        severity = Severity.HIGH if divergence >= 0.85 else Severity.MEDIUM
        return DetectorSignal(
            detector=self.name,
            plane=Plane.CONTENT,
            score=divergence,
            locus=Locus.RESPONSE,
            signal_type="response_not_entailed",
            severity=severity,
            rationale=(
                "grounding context does not entail the response "
                f"(divergence {divergence:.2f})"
            ),
        )
