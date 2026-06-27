# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — LLM judge / panel tests (injected judge fns; no model)

from __future__ import annotations

import pytest

from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.core import (
    EvaluationRequest,
    ParallelEnsembleScorer,
    Plane,
    Severity,
)
from director_class_ai.detectors import (
    JudgePanel,
    JudgeResult,
    JudgeSpec,
    LLMJudgeDetector,
    prompt_judge,
)
from director_class_ai.detectors.llm_judge import _coerce_probability, _score_from_json


def const_judge(score: float, rationale: str = "r"):
    return lambda _request: JudgeResult(score=score, rationale=rationale)


class TestPromptJudge:
    def test_parses_score_from_completion(self) -> None:
        j = prompt_judge(lambda _p: "risk: 0.8", lens="is it safe?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.8)

    def test_parses_json_risk_field(self) -> None:
        j = prompt_judge(lambda _p: '{"risk": 0.7, "reason": "quoted"}', lens="?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.7)

    def test_parses_json_score_field(self) -> None:
        j = prompt_judge(lambda _p: '{"score": "0.6"}', lens="?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.6)

    @pytest.mark.parametrize(
        "completion",
        [
            '{"risk": true}',
            '{"risk": "not-a-number"}',
            '{"risk": 1.5}',
            "{bad json",
        ],
    )
    def test_rejects_non_probability_json_scores(self, completion: str) -> None:
        j = prompt_judge(lambda _p: completion, lens="?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.0)

    def test_non_mapping_json_can_still_fall_back_to_text_score(self) -> None:
        j = prompt_judge(lambda _p: '["risk", 0.7]', lens="?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.7)

    def test_probability_helpers_reject_unscored_objects(self) -> None:
        assert _coerce_probability(object()) is None
        assert _score_from_json('{"reason":"safe"}') is None

    def test_uses_last_numeric_token_only_when_it_is_a_probability(self) -> None:
        j = prompt_judge(lambda _p: "safe after review; final score 0.2", lens="?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.2)

    def test_ignores_unanchored_one_of_ten_safe_text(self) -> None:
        j = prompt_judge(lambda _p: "risk level 1 of 10, totally safe", lens="?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.0)

    def test_unsafe_keyword_fallback(self) -> None:
        j = prompt_judge(lambda _p: "this is UNSAFE", lens="?")
        assert j(EvaluationRequest(response="x")).score == pytest.approx(0.85)

    def test_no_signal_defaults_safe(self) -> None:
        j = prompt_judge(lambda _p: "looks fine to me", lens="?")
        assert j(EvaluationRequest(response="x")).score == 0.0

    def test_prompt_includes_subject_and_lens(self) -> None:
        seen = {}

        def complete(prompt: str) -> str:
            seen["p"] = prompt
            return "0.1"

        prompt_judge(complete, lens="LENS-MARKER")(
            EvaluationRequest(query="Q", response="R")
        )
        assert "LENS-MARKER" in seen["p"] and "R" in seen["p"]

    def test_score_clamped(self) -> None:
        j = prompt_judge(lambda _p: "0.99", lens="?")
        assert 0.0 <= j(EvaluationRequest(response="x")).score <= 1.0


class TestLLMJudgeDetector:
    def test_emits_above_floor(self) -> None:
        det = LLMJudgeDetector(
            const_judge(0.9), name="j", plane=Plane.CONTENT, signal_type="t"
        )
        sig = det.evaluate(EvaluationRequest(response="x"))
        assert sig is not None and sig.score == pytest.approx(0.9)

    def test_silent_below_floor(self) -> None:
        det = LLMJudgeDetector(
            const_judge(0.05), name="j", plane=Plane.CONTENT, signal_type="t"
        )
        assert det.evaluate(EvaluationRequest(response="x")) is None

    def test_samples_must_be_positive(self) -> None:
        with pytest.raises(ValueError, match="samples"):
            LLMJudgeDetector(
                const_judge(0.5),
                name="j",
                plane=Plane.CONTENT,
                signal_type="t",
                samples=0,
            )

    def test_self_consistency_averages_and_calibrates(self) -> None:
        # alternating 0.4 / 1.0 over samples -> mean 0.7, spread 0.6 -> calibration 0.4
        scores = iter([0.4, 1.0, 0.4, 1.0])

        def flaky(_request):
            return JudgeResult(score=next(scores))

        det = LLMJudgeDetector(
            flaky, name="j", plane=Plane.CONTENT, signal_type="t", samples=4
        )
        sig = det.evaluate(EvaluationRequest(response="x"))
        assert sig.score == pytest.approx(0.7)
        assert sig.calibration == pytest.approx(0.4)

    def test_never_clears_a_deterministic_block(self) -> None:
        # a judge insisting an action is safe cannot un-block a destructive command
        safe_judge = LLMJudgeDetector(
            const_judge(0.0), name="lenient", plane=Plane.ACTION, signal_type="t"
        )
        ens = ParallelEnsembleScorer([DestructiveCommandDetector(), safe_judge])
        v = ens.evaluate(EvaluationRequest(action="rm -rf /"))
        assert v.allow is False  # deterministic block stands


class TestJudgePanel:
    def test_builds_one_detector_per_spec(self) -> None:
        panel = JudgePanel(
            specs=[
                JudgeSpec(const_judge(0.9), name="safety", plane=Plane.ACTION),
                JudgeSpec(const_judge(0.9), name="grounding", plane=Plane.CONTENT),
            ]
        )
        dets = panel.detectors()
        assert [d.name for d in dets] == ["safety", "grounding"]
        assert all(d.tier == 2 for d in dets)

    def test_panel_in_ensemble_escalates_on_split(self) -> None:
        # one judge flags content, one stays quiet -> mid-range fused risk -> review
        panel = JudgePanel(
            specs=[
                JudgeSpec(const_judge(0.4), name="a", plane=Plane.CONTENT),
                JudgeSpec(const_judge(0.0), name="b", plane=Plane.CONTENT),
            ]
        )
        ens = ParallelEnsembleScorer(panel.detectors())
        v = ens.evaluate(EvaluationRequest(response="x"))
        assert v.requires_human is True

    def test_spec_severity_carried(self) -> None:
        panel = JudgePanel(
            specs=[JudgeSpec(const_judge(0.9), name="s", severity=Severity.CRITICAL)]
        )
        assert panel.detectors()[0]._severity is Severity.CRITICAL
