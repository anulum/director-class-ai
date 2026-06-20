# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — contradiction content adapter

"""Wrap director-ai's contradiction scorer as a content Detector.

Scores ``P(contradiction)`` of the response against the grounding context and
emits a content-plane signal when it crosses a threshold. This is the detector
that complements the token-span detector: token-span catches baseless additions,
contradiction catches claims that conflict with the context. The model is loaded
lazily via ``from_pretrained``.
"""

from __future__ import annotations

from typing import Any

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane

__all__ = ["ContradictionContentDetector"]


class ContradictionContentDetector:
    """Content-plane adapter over director-ai's ContradictionScorer."""

    name = "contradiction"
    plane = Plane.CONTENT
    tier = 1

    def __init__(self, scorer: Any, *, threshold: float = 0.5) -> None:
        self._scorer = scorer
        self._threshold = float(threshold)

    @classmethod
    def from_pretrained(
        cls, *, threshold: float = 0.5, **kwargs: Any
    ) -> (
        ContradictionContentDetector
    ):  # pragma: no cover - needs [detectors] extra + model
        """Load the optional director-ai contradiction scorer."""
        from director_ai.core.scoring.contradiction import ContradictionScorer

        return cls(ContradictionScorer.from_pretrained(**kwargs), threshold=threshold)

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Emit a contradiction signal when response and context conflict."""
        if not request.response.strip() or not request.context.strip():
            return None
        score = float(self._scorer.contradiction(request.context, request.response))
        if score < self._threshold:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.CONTENT,
            score=score,
            locus=Locus.RESPONSE,
            signal_type="contradiction",
            rationale="response contradicts the grounding context",
        )
