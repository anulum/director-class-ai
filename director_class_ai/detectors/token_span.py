# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — token-span content adapter

"""Wrap director-ai's token-level hallucinated-span detector as a content Detector.

It maps the span detection (which response tokens are unsupported by the context)
onto a content-plane :class:`DetectorSignal`: the score is the strongest flagged
token probability and the flagged character ranges become the signal's spans, so
the fusion layer and the caller learn *which* phrases are unsupported, not just
that the answer is ungrounded. The model is loaded lazily via ``from_pretrained``.
"""

from __future__ import annotations

from typing import Any

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane, Span

__all__ = ["TokenSpanContentDetector"]


class TokenSpanContentDetector:
    """Content-plane adapter over director-ai's HallucinationSpanDetector."""

    name = "token_span"
    plane = Plane.CONTENT
    tier = 1  # model-backed: runs after the cheap tier-0 detectors

    def __init__(self, detector: Any) -> None:
        self._detector = detector

    @classmethod
    def from_pretrained(
        cls, **kwargs: Any
    ) -> TokenSpanContentDetector:  # pragma: no cover - needs [detectors] extra + model
        """Load the optional director-ai hallucinated-span detector."""
        from director_ai.core.scoring.span_detector import HallucinationSpanDetector

        return cls(HallucinationSpanDetector.from_pretrained(**kwargs))

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Emit unsupported-span signals for hallucinated response text."""
        if not request.response.strip():
            return None
        detection = self._detector.detect(request.context, request.response)
        if not detection.hallucinated:
            return None
        spans = tuple(
            Span(start=s.start, end=s.end, score=s.score) for s in detection.spans
        )
        return DetectorSignal(
            detector=self.name,
            plane=Plane.CONTENT,
            score=float(detection.max_token_score),
            locus=Locus.SPAN,
            signal_type="baseless_span",
            spans=spans,
            rationale=f"{detection.flagged_tokens} unsupported response token(s)",
        )
