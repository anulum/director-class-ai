# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — semantic action-support detector tests (injected scorer)

from __future__ import annotations

from director_class_ai.core import EvaluationRequest, Plane, Severity
from director_class_ai.detectors import SemanticActionSupportDetector, SupportScorer


class _FakeScorer:
    """Records the (premise, hypothesis) it is asked about; returns a fixed value."""

    def __init__(self, divergence: float) -> None:
        self._value = divergence
        self.calls: list[tuple[str, str]] = []

    def score(self, premise: str, hypothesis: str) -> float:
        self.calls.append((premise, hypothesis))
        return self._value


def _req(query: str, action: str) -> EvaluationRequest:
    return EvaluationRequest(query=query, action=action)


class TestGating:
    def test_read_only_action_is_not_scored(self) -> None:
        scorer = _FakeScorer(0.99)
        det = SemanticActionSupportDetector(scorer)
        assert det.evaluate(_req("summarise the report", "cat report.txt")) is None
        assert scorer.calls == []  # the model is never spent on a read

    def test_missing_task_or_action_returns_none(self) -> None:
        det = SemanticActionSupportDetector(_FakeScorer(0.99))
        assert det.evaluate(_req("", "rm -rf /tmp/x")) is None
        assert det.evaluate(_req("clean up", "   ")) is None


class TestSupportDecision:
    def test_unsupported_mutation_flags(self) -> None:
        det = SemanticActionSupportDetector(_FakeScorer(0.8))
        sig = det.evaluate(_req("summarise the quarterly report", "DROP TABLE users"))
        assert sig is not None
        assert sig.plane is Plane.ACTION
        assert sig.signal_type == "action_not_supported"
        assert sig.score == 0.8

    def test_supported_mutation_returns_none(self) -> None:
        det = SemanticActionSupportDetector(_FakeScorer(0.1))
        assert det.evaluate(_req("delete the temp files", "rm /tmp/scratch")) is None

    def test_threshold_boundary_is_inclusive(self) -> None:
        det = SemanticActionSupportDetector(_FakeScorer(0.6), threshold=0.6)
        assert det.evaluate(_req("read the logs", "git push --force")) is not None

    def test_custom_threshold(self) -> None:
        det = SemanticActionSupportDetector(_FakeScorer(0.4), threshold=0.3)
        assert det.evaluate(_req("read the logs", "git push origin main")) is not None


class TestSeverity:
    def test_irreversible_unauthorised_is_high(self) -> None:
        det = SemanticActionSupportDetector(_FakeScorer(0.9))
        sig = det.evaluate(_req("show me the database", "rm -rf /var/lib/postgres"))
        assert sig is not None and sig.severity is Severity.HIGH

    def test_reversible_mutation_is_medium(self) -> None:
        det = SemanticActionSupportDetector(_FakeScorer(0.9))
        sig = det.evaluate(_req("list the branches", "git push origin main"))
        assert sig is not None and sig.severity is Severity.MEDIUM

    def test_irreversible_but_authorised_task_is_medium(self) -> None:
        # the task explicitly authorised a delete, so even a divergent irreversible
        # action is only MEDIUM — the user did ask to remove something.
        det = SemanticActionSupportDetector(_FakeScorer(0.9))
        sig = det.evaluate(_req("delete the old backups", "rm -rf /data/prod"))
        assert sig is not None and sig.severity is Severity.MEDIUM


class TestScorerContract:
    def test_task_is_premise_and_action_is_in_hypothesis(self) -> None:
        scorer = _FakeScorer(0.9)
        SemanticActionSupportDetector(scorer).evaluate(
            _req("read the config", "rm -rf /etc")
        )
        (premise, hypothesis) = scorer.calls[0]
        assert premise == "read the config"
        assert "rm -rf /etc" in hypothesis

    def test_protocol_is_satisfied_by_a_score_method(self) -> None:
        assert isinstance(_FakeScorer(0.5), SupportScorer)
