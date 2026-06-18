# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — PII content adapter tests

from __future__ import annotations

from dataclasses import dataclass

import pytest

from director_class_ai.core import EvaluationRequest, Locus, Plane
from director_class_ai.detectors import PIIContentDetector


@dataclass(frozen=True)
class _Match:
    category: str
    start: int
    end: int
    score: float = 1.0


@dataclass(frozen=True)
class _Result:
    matches: tuple[_Match, ...]


class _Backend:
    def __init__(self, result: _Result) -> None:
        self._result = result
        self.calls: list[str] = []

    def analyse(self, text: str) -> _Result:
        self.calls.append(text)
        return self._result


class TestPIIContentDetector:
    def test_response_pii_maps_to_span_signal(self) -> None:
        backend = _Backend(_Result((_Match("email", 8, 23, 0.93),)))
        detector = PIIContentDetector(backend)

        signal = detector.evaluate(
            EvaluationRequest(response="Contact a@b.example for details.")
        )

        assert signal is not None
        assert signal.plane is Plane.CONTENT
        assert signal.locus is Locus.RESPONSE
        assert signal.signal_type == "pii_detected"
        assert signal.score == 0.93
        assert signal.spans[0].start == 8
        assert signal.spans[0].end == 23
        assert signal.rationale == "1 PII finding(s) in response: email:1"
        assert backend.calls == ["Contact a@b.example for details."]

    def test_sensitive_category_raises_severity(self) -> None:
        detector = PIIContentDetector(_Backend(_Result((_Match("ssn", 4, 15, 1.0),))))

        signal = detector.evaluate(EvaluationRequest(response="SSN 123-45-6789"))

        assert signal is not None
        assert signal.severity.name == "HIGH"

    def test_query_scan_uses_input_locus(self) -> None:
        backend = _Backend(_Result((_Match("phone", 5, 17, 0.8),)))
        detector = PIIContentDetector(backend, field="query")

        signal = detector.evaluate(EvaluationRequest(query="call 555-010-9999"))

        assert signal is not None
        assert signal.locus is Locus.INPUT
        assert backend.calls == ["call 555-010-9999"]

    def test_context_scan_is_explicit(self) -> None:
        backend = _Backend(_Result((_Match("email", 0, 11, 0.8),)))
        detector = PIIContentDetector(backend, field="context")

        signal = detector.evaluate(EvaluationRequest(context="a@b.example"))

        assert signal is not None
        assert signal.locus is Locus.INPUT
        assert backend.calls == ["a@b.example"]

    def test_empty_selected_field_returns_none_without_backend_call(self) -> None:
        backend = _Backend(_Result((_Match("email", 0, 11, 1.0),)))
        detector = PIIContentDetector(backend)

        assert detector.evaluate(EvaluationRequest(response="   ")) is None
        assert backend.calls == []

    def test_below_threshold_and_invalid_spans_are_dropped(self) -> None:
        detector = PIIContentDetector(
            _Backend(
                _Result(
                    (
                        _Match("email", 0, 11, 0.2),
                        _Match("phone", -1, 5, 1.0),
                        _Match("ssn", 4, 99, 1.0),
                    )
                )
            ),
            threshold=0.5,
        )

        assert detector.evaluate(EvaluationRequest(response="a@b.example")) is None

    def test_multiple_categories_are_summarised_without_raw_values(self) -> None:
        detector = PIIContentDetector(
            _Backend(
                _Result(
                    (
                        _Match("phone", 0, 4, 0.8),
                        _Match("email", 5, 16, 0.7),
                        _Match("email", 17, 28, 0.9),
                    )
                )
            )
        )

        signal = detector.evaluate(
            EvaluationRequest(response="1234 a@b.example c@d.example")
        )

        assert signal is not None
        assert signal.score == 0.9
        assert signal.rationale == "3 PII finding(s) in response: email:2, phone:1"

    @pytest.mark.parametrize("threshold", [-0.1, 1.1])
    def test_threshold_must_be_probability(self, threshold: float) -> None:
        with pytest.raises(ValueError, match="threshold must be in \\[0, 1\\]"):
            PIIContentDetector(_Backend(_Result(())), threshold=threshold)
