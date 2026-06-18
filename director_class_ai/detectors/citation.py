# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — citation coverage content adapter

"""Citation-trace adapter for claim-level grounding coverage.

The upstream citation tracer links response claim sentences to inline citations
using deterministic character-offset mapping. This adapter turns that trace into
a content-plane signal when claim coverage falls below the configured operating
threshold. It does not judge whether a citation supports the claim; it flags
uncited claims as review candidates so the ensemble can combine citation hygiene
with entailment and span-level grounding evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Protocol, runtime_checkable

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane, Severity

__all__ = [
    "CitationCoverageDetector",
    "CitationTrace",
    "CitationTracer",
]


@runtime_checkable
class CitationTrace(Protocol):
    """Citation tracing result consumed by :class:`CitationCoverageDetector`."""

    @property
    def coverage(self) -> float:
        """Return the fraction of claim sentences carrying inline citations."""
        ...

    @property
    def claims(self) -> Sequence[object]:
        """Return all claim records observed in the response body."""
        ...

    @property
    def uncited(self) -> Sequence[object]:
        """Return claim records that did not carry an inline citation."""
        ...


CitationTracer = Callable[[str], CitationTrace]


class CitationCoverageDetector:
    """Tier-0 content detector for uncited response claims."""

    name = "citation_coverage"
    plane = Plane.CONTENT
    tier = 0

    def __init__(
        self,
        tracer: CitationTracer,
        *,
        min_coverage: float = 0.8,
        min_claims: int = 1,
    ) -> None:
        """Create a citation coverage detector.

        Parameters
        ----------
        tracer:
            Callable that maps response text to a citation trace. Tests inject a
            lightweight deterministic tracer; :meth:`from_pretrained` wires the
            optional Director-AI citation tracer.
        min_coverage:
            Minimum acceptable fraction of claim sentences with inline
            citations. Values must be in ``[0, 1]``.
        min_claims:
            Minimum number of detected claims required before emitting a signal.
            This avoids flagging short answers whose citation trace is empty.

        Raises
        ------
        ValueError
            If ``min_coverage`` is outside ``[0, 1]`` or ``min_claims`` is
            smaller than one.
        """
        if not 0.0 <= min_coverage <= 1.0:
            raise ValueError(f"min_coverage must be in [0, 1], got {min_coverage}")
        if min_claims < 1:
            raise ValueError(f"min_claims must be >= 1, got {min_claims}")
        self._tracer = tracer
        self._min_coverage = float(min_coverage)
        self._min_claims = int(min_claims)

    @classmethod
    def from_pretrained(
        cls, *, min_coverage: float = 0.8, min_claims: int = 1
    ) -> CitationCoverageDetector:  # pragma: no cover - needs [detectors] extra
        """Load the optional Director-AI citation tracer."""
        from director_ai import trace_citations

        return cls(
            trace_citations,
            min_coverage=min_coverage,
            min_claims=min_claims,
        )

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Emit a claim-level content signal when citation coverage is low."""
        response = request.response.strip()
        if not response:
            return None
        trace = self._tracer(response)
        total_claims = len(trace.claims)
        if total_claims < self._min_claims or not trace.uncited:
            return None
        coverage = float(trace.coverage)
        if coverage >= self._min_coverage:
            return None
        uncited_count = len(trace.uncited)
        uncited_share = uncited_count / total_claims
        severity = (
            Severity.HIGH if coverage == 0.0 and total_claims > 1 else Severity.MEDIUM
        )
        return DetectorSignal(
            detector=self.name,
            plane=Plane.CONTENT,
            score=min(1.0, max(0.0, uncited_share)),
            locus=Locus.CLAIM,
            signal_type="uncited_claims",
            severity=severity,
            rationale=(
                f"{uncited_count}/{total_claims} claim(s) lack inline citations "
                f"(coverage {coverage:.2f}, required {self._min_coverage:.2f})"
            ),
        )
