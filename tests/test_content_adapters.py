# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — content adapter tests (injected fakes; no model load)

from __future__ import annotations

from dataclasses import dataclass

from director_class_ai.core import EvaluationRequest, Locus, Plane
from director_class_ai.detectors import (
    ContradictionContentDetector,
    ResponseNLIDetector,
    TokenSpanContentDetector,
)


@dataclass
class _FakeSpan:
    start: int
    end: int
    score: float


@dataclass
class _FakeDetection:
    hallucinated: bool
    spans: tuple
    max_token_score: float
    flagged_tokens: int


class _FakeSpanModel:
    def __init__(self, detection: _FakeDetection) -> None:
        self._d = detection

    def detect(self, context: str, response: str) -> _FakeDetection:
        return self._d


class TestTokenSpanAdapter:
    def test_hallucinated_maps_to_signal_with_spans(self) -> None:
        det = _FakeDetection(True, (_FakeSpan(6, 11, 0.96),), 0.96, 1)
        adapter = TokenSpanContentDetector(_FakeSpanModel(det))
        sig = adapter.evaluate(EvaluationRequest(context="c", response="it is wrong"))
        assert sig is not None
        assert sig.plane is Plane.CONTENT and sig.locus is Locus.SPAN
        assert sig.signal_type == "baseless_span"
        assert sig.score == 0.96
        assert sig.spans[0].start == 6 and sig.spans[0].end == 11

    def test_grounded_returns_none(self) -> None:
        det = _FakeDetection(False, (), 0.1, 0)
        adapter = TokenSpanContentDetector(_FakeSpanModel(det))
        assert adapter.evaluate(EvaluationRequest(response="grounded")) is None

    def test_empty_response_returns_none(self) -> None:
        adapter = TokenSpanContentDetector(
            _FakeSpanModel(_FakeDetection(True, (), 1.0, 1))
        )
        assert adapter.evaluate(EvaluationRequest(response="   ")) is None


class _FakeContradictionScorer:
    def __init__(self, value: float) -> None:
        self._value = value

    def contradiction(self, premise: str, hypothesis: str) -> float:
        return self._value


class TestContradictionAdapter:
    def test_above_threshold_flags(self) -> None:
        adapter = ContradictionContentDetector(_FakeContradictionScorer(0.9))
        sig = adapter.evaluate(EvaluationRequest(context="c", response="r"))
        assert sig is not None
        assert sig.signal_type == "contradiction"
        assert sig.score == 0.9

    def test_below_threshold_returns_none(self) -> None:
        adapter = ContradictionContentDetector(_FakeContradictionScorer(0.2))
        assert adapter.evaluate(EvaluationRequest(context="c", response="r")) is None

    def test_custom_threshold(self) -> None:
        adapter = ContradictionContentDetector(
            _FakeContradictionScorer(0.4), threshold=0.3
        )
        assert adapter.evaluate(EvaluationRequest(context="c", response="r")) is not None

    def test_missing_context_or_response_returns_none(self) -> None:
        adapter = ContradictionContentDetector(_FakeContradictionScorer(0.9))
        assert adapter.evaluate(EvaluationRequest(response="r")) is None
        assert adapter.evaluate(EvaluationRequest(context="c")) is None


class _FakeResponseNLIScorer:
    def __init__(self, value: float) -> None:
        self._value = value
        self.calls: list[tuple[str, str]] = []

    def score(self, premise: str, hypothesis: str) -> float:
        self.calls.append((premise, hypothesis))
        return self._value


class TestResponseNLIAdapter:
    def test_divergent_response_flags_content_signal(self) -> None:
        scorer = _FakeResponseNLIScorer(0.72)
        adapter = ResponseNLIDetector(scorer)
        sig = adapter.evaluate(
            EvaluationRequest(context="The value is 10.", response="The value is 12.")
        )

        assert sig is not None
        assert sig.plane is Plane.CONTENT and sig.locus is Locus.RESPONSE
        assert sig.signal_type == "response_not_entailed"
        assert sig.score == 0.72
        assert sig.rationale.endswith("(divergence 0.72)")
        assert scorer.calls == [("The value is 10.", "The value is 12.")]

    def test_high_divergence_raises_severity(self) -> None:
        adapter = ResponseNLIDetector(_FakeResponseNLIScorer(0.91))
        sig = adapter.evaluate(EvaluationRequest(context="A", response="B"))

        assert sig is not None
        assert sig.severity.name == "HIGH"

    def test_below_threshold_returns_none(self) -> None:
        adapter = ResponseNLIDetector(_FakeResponseNLIScorer(0.2))
        assert adapter.evaluate(EvaluationRequest(context="A", response="A")) is None

    def test_custom_threshold(self) -> None:
        adapter = ResponseNLIDetector(_FakeResponseNLIScorer(0.4), threshold=0.3)
        assert adapter.evaluate(EvaluationRequest(context="A", response="B")) is not None

    def test_missing_context_or_response_returns_none(self) -> None:
        adapter = ResponseNLIDetector(_FakeResponseNLIScorer(0.9))
        assert adapter.evaluate(EvaluationRequest(response="r")) is None
        assert adapter.evaluate(EvaluationRequest(context="c")) is None
