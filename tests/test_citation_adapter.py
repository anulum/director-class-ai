# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — citation coverage adapter tests

from __future__ import annotations

from dataclasses import dataclass

import pytest

from director_class_ai.core import EvaluationRequest, Locus, Plane
from director_class_ai.detectors import CitationCoverageDetector


@dataclass(frozen=True)
class _Claim:
    text: str


@dataclass(frozen=True)
class _Trace:
    coverage: float
    claims: tuple[_Claim, ...]
    uncited: tuple[_Claim, ...]


class _FakeTracer:
    def __init__(self, trace: _Trace) -> None:
        self._trace = trace
        self.calls: list[str] = []

    def __call__(self, text: str) -> _Trace:
        self.calls.append(text)
        return self._trace


class TestCitationCoverageDetector:
    def test_low_citation_coverage_flags_uncited_claims(self) -> None:
        tracer = _FakeTracer(
            _Trace(
                coverage=0.5,
                claims=(_Claim("A."), _Claim("B.")),
                uncited=(_Claim("B."),),
            )
        )
        detector = CitationCoverageDetector(tracer, min_coverage=0.8)

        signal = detector.evaluate(EvaluationRequest(response=" A [1]. B. "))

        assert signal is not None
        assert signal.plane is Plane.CONTENT
        assert signal.locus is Locus.CLAIM
        assert signal.signal_type == "uncited_claims"
        assert signal.score == 0.5
        assert signal.rationale == (
            "1/2 claim(s) lack inline citations (coverage 0.50, required 0.80)"
        )
        assert tracer.calls == ["A [1]. B."]

    def test_zero_coverage_over_multiple_claims_raises_severity(self) -> None:
        detector = CitationCoverageDetector(
            _FakeTracer(
                _Trace(
                    coverage=0.0,
                    claims=(_Claim("A."), _Claim("B.")),
                    uncited=(_Claim("A."), _Claim("B.")),
                )
            )
        )

        signal = detector.evaluate(EvaluationRequest(response="A. B."))

        assert signal is not None
        assert signal.score == 1.0
        assert signal.severity.name == "HIGH"

    def test_sufficient_coverage_returns_none(self) -> None:
        detector = CitationCoverageDetector(
            _FakeTracer(
                _Trace(
                    coverage=0.9,
                    claims=(_Claim("A."), _Claim("B.")),
                    uncited=(_Claim("B."),),
                )
            ),
            min_coverage=0.8,
        )

        assert detector.evaluate(EvaluationRequest(response="A [1]. B.")) is None

    def test_no_uncited_claims_returns_none(self) -> None:
        detector = CitationCoverageDetector(
            _FakeTracer(_Trace(coverage=1.0, claims=(_Claim("A."),), uncited=()))
        )

        assert detector.evaluate(EvaluationRequest(response="A [1].")) is None

    def test_min_claims_suppresses_short_trace(self) -> None:
        detector = CitationCoverageDetector(
            _FakeTracer(
                _Trace(coverage=0.0, claims=(_Claim("A."),), uncited=(_Claim("A."),))
            ),
            min_claims=2,
        )

        assert detector.evaluate(EvaluationRequest(response="A.")) is None

    def test_empty_response_returns_none_without_calling_tracer(self) -> None:
        tracer = _FakeTracer(_Trace(coverage=0.0, claims=(), uncited=()))
        detector = CitationCoverageDetector(tracer)

        assert detector.evaluate(EvaluationRequest(response="   ")) is None
        assert tracer.calls == []

    @pytest.mark.parametrize("min_coverage", [-0.1, 1.1])
    def test_min_coverage_must_be_probability(self, min_coverage: float) -> None:
        with pytest.raises(ValueError, match="min_coverage must be in \\[0, 1\\]"):
            CitationCoverageDetector(
                _FakeTracer(_Trace(coverage=1.0, claims=(), uncited=())),
                min_coverage=min_coverage,
            )

    def test_min_claims_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="min_claims must be >= 1"):
            CitationCoverageDetector(
                _FakeTracer(_Trace(coverage=1.0, claims=(), uncited=())),
                min_claims=0,
            )
