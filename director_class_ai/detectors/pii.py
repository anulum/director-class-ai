# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — PII content adapter

"""Adapter for structured PII moderation findings.

Director-AI's moderation detectors report structured spans and categories, while
Director-Class AI fuses every detector through :class:`DetectorSignal`. This
module bridges those surfaces without importing Director-AI at package import
time. The default operating mode scans response text for sensitive-data leakage;
callers that need ingress scanning can explicitly select the query or context
field.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from typing import Literal, Protocol, runtime_checkable

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane, Severity, Span

__all__ = [
    "PIIContentDetector",
    "PIIMatch",
    "PIIModerationBackend",
    "PIIModerationResult",
]

PIIField = Literal["response", "query", "context"]

_SENSITIVE_CATEGORIES = frozenset({"credit_card", "ssn", "phi", "iban", "passport"})


@runtime_checkable
class PIIMatch(Protocol):
    """One sensitive-data finding produced by a moderation backend."""

    category: str
    start: int
    end: int
    score: float


@runtime_checkable
class PIIModerationResult(Protocol):
    """Structured result returned by a PII moderation backend."""

    matches: Sequence[PIIMatch]


@runtime_checkable
class PIIModerationBackend(Protocol):
    """Detector backend with the Director-AI moderation surface."""

    def analyse(self, text: str) -> PIIModerationResult:
        """Return PII matches for ``text`` without mutating backend state."""
        ...


class PIIContentDetector:
    """Content-plane adapter for response, query, or context PII findings."""

    name = "pii_content"
    plane = Plane.CONTENT
    tier = 0

    def __init__(
        self,
        backend: PIIModerationBackend,
        *,
        field: PIIField = "response",
        threshold: float = 0.5,
    ) -> None:
        """Create a PII detector adapter.

        Parameters
        ----------
        backend:
            Moderation backend exposing ``analyse(text).matches`` with category,
            start, end, and score attributes.
        field:
            Request field to scan. The default scans response text for outgoing
            sensitive-data leakage. Query and context scanning are explicit so
            callers do not accidentally classify private grounding material as a
            response leak.
        threshold:
            Minimum match score required before a finding contributes to the
            emitted signal. Values must be in ``[0, 1]``.

        Raises
        ------
        ValueError
            If ``threshold`` is outside ``[0, 1]``.
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1], got {threshold}")
        self._backend = backend
        self._field = field
        self._threshold = float(threshold)

    @classmethod
    def from_regex(
        cls,
        *,
        field: PIIField = "response",
        threshold: float = 0.5,
        prefer_rust: bool = True,
    ) -> PIIContentDetector:  # pragma: no cover - needs [detectors] extra
        """Load Director-AI's dependency-light regex PII detector."""
        from director_ai.core.safety.moderation import RegexPIIDetector

        return cls(
            RegexPIIDetector(prefer_rust=prefer_rust),
            field=field,
            threshold=threshold,
        )

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Emit a span-level content signal when PII appears in the scanned field."""
        text = self._field_text(request).strip()
        if not text:
            return None
        result = self._backend.analyse(text)
        matches = [
            match
            for match in result.matches
            if match.score >= self._threshold
            and 0 <= match.start < match.end <= len(text)
        ]
        if not matches:
            return None
        spans = tuple(
            Span(
                start=match.start,
                end=match.end,
                score=min(1.0, max(0.0, match.score)),
            )
            for match in matches
        )
        categories = Counter(match.category for match in matches)
        category_summary = ", ".join(
            f"{category}:{count}" for category, count in sorted(categories.items())
        )
        max_score = max(span.score for span in spans)
        severity = (
            Severity.HIGH
            if any(match.category in _SENSITIVE_CATEGORIES for match in matches)
            else Severity.MEDIUM
        )
        return DetectorSignal(
            detector=self.name,
            plane=Plane.CONTENT,
            score=max_score,
            locus=self._locus(),
            signal_type="pii_detected",
            severity=severity,
            spans=spans,
            rationale=(
                f"{len(matches)} PII finding(s) in {self._field}: {category_summary}"
            ),
        )

    def _field_text(self, request: EvaluationRequest) -> str:
        """Return the configured request field."""
        if self._field == "query":
            return request.query
        if self._field == "context":
            return request.context
        return request.response

    def _locus(self) -> Locus:
        """Return the signal locus for the configured request field."""
        if self._field == "query":
            return Locus.INPUT
        if self._field == "context":
            return Locus.INPUT
        return Locus.RESPONSE
