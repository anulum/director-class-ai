# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — LLM-judge detector and judge panel

"""LLM judges as ensemble detectors — the generalising, escalation-only tier.

Rules and small models enumerate known threats; an LLM judge *generalises* to the
ones no one enumerated — a novel destructive idiom, a semantic-equivalent of a
blocked command, an action that does not fit the stated task. It is the most
capable detector and the most expensive and least trustworthy (it can hallucinate
and be injected), so it sits at a high tier (escalation-only) and obeys two rules
baked into the design:

* **It only ever raises risk.** A judge emits a *problem* score, never an "allow"
  — so a judge that is wrong or injected can escalate or block, but can never
  clear a deterministic block. The fail-closed invariant survives a compromised
  judge.
* **Diversity over duplication.** Duplicating one judge is worthless; a *panel* of
  judges that differ — different base models, different specialised lenses
  (destructive-action, grounding, intent, domain compliance) — has uncorrelated
  errors. Their agreement is confidence; their disagreement lands the fused risk
  in the uncertainty band and escalates to a human.

Self-consistency: a single judge is stochastic, so it can be sampled N times and
averaged; the sample spread is folded into the signal's calibration (an
inconsistent judge is trusted less). The judge function is injected
(provider-agnostic); :func:`prompt_judge` builds one from any text-completion
callable.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane, Severity

__all__ = [
    "JudgeResult",
    "JudgeFn",
    "LLMJudgeDetector",
    "JudgeSpec",
    "JudgePanel",
    "prompt_judge",
]


@dataclass(frozen=True)
class JudgeResult:
    """One judge call: probability of a problem, with a short reason."""

    score: float
    rationale: str = ""


JudgeFn = Callable[[EvaluationRequest], JudgeResult]

_SCORE_RE = re.compile(r"(?:0?\.\d+|[01](?:\.0+)?)")


def prompt_judge(
    complete: Callable[[str], str],
    *,
    lens: str,
    locus_field: str = "response",
) -> JudgeFn:
    """Build a JudgeFn from a text-completion callable and a lens instruction.

    The completion is asked for a 0–1 risk; the parser is tolerant (first float in
    range, or the word "unsafe"/"safe"). ``complete`` is provider-agnostic — wire
    any LLM client (director-ai's judge, OpenAI, a local model) behind it.
    """

    def judge(request: EvaluationRequest) -> JudgeResult:
        subject = getattr(request, locus_field, "") or ""
        prompt = (
            f"{lens}\n\nTask: {request.query}\nContext: {request.context}\n"
            f"Subject: {subject}\nAction: {request.action}\n\n"
            "Reply with a single risk score from 0 (safe) to 1 (problem)."
        )
        text = complete(prompt) or ""
        match = _SCORE_RE.search(text)
        if match:
            score = max(0.0, min(1.0, float(match.group())))
        else:
            score = 0.85 if "unsafe" in text.lower() else 0.0
        return JudgeResult(score=score, rationale=text.strip()[:200])

    return judge


class LLMJudgeDetector:
    """An LLM judge as a detector — escalation-only, raises risk only."""

    def __init__(
        self,
        judge_fn: JudgeFn,
        *,
        name: str,
        plane: Plane,
        signal_type: str,
        tier: int = 2,
        samples: int = 1,
        emit_floor: float = 0.2,
        severity: Severity = Severity.HIGH,
        locus: Locus = Locus.RESPONSE,
    ) -> None:
        if samples < 1:
            raise ValueError("samples must be >= 1")
        self._judge_fn = judge_fn
        self.name = name
        self.plane = plane
        self._signal_type = signal_type
        self.tier = tier
        self._samples = samples
        self._emit_floor = emit_floor
        self._severity = severity
        self._locus = locus

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        results = [self._judge_fn(request) for _ in range(self._samples)]
        scores = [r.score for r in results]
        mean = sum(scores) / len(scores)
        if mean < self._emit_floor:
            return None  # the judge is confident this is fine
        spread = max(scores) - min(scores)  # 0 = consistent, 1 = self-contradictory
        calibration = max(0.0, 1.0 - spread)  # trust an inconsistent judge less
        rationale = next((r.rationale for r in results if r.rationale), "")
        return DetectorSignal(
            detector=self.name,
            plane=self.plane,
            score=mean,
            locus=self._locus,
            signal_type=self._signal_type,
            severity=self._severity,
            calibration=calibration,
            rationale=rationale,
        )


@dataclass(frozen=True)
class JudgeSpec:
    """Configuration for one judge in a panel."""

    judge_fn: JudgeFn
    name: str
    plane: Plane = Plane.CONTENT
    signal_type: str = "llm_judge"
    samples: int = 1
    severity: Severity = Severity.HIGH
    locus: Locus = Locus.RESPONSE


@dataclass
class JudgePanel:
    """A panel of diverse / specialised LLM judges, built into detectors.

    Each spec becomes an :class:`LLMJudgeDetector` at the same (high) tier, so the
    ensemble runs them concurrently and the fusion aggregates their verdicts —
    agreement raises confidence, disagreement escalates to a human.
    """

    specs: Sequence[JudgeSpec] = field(default_factory=tuple)
    tier: int = 2

    def detectors(self) -> list[LLMJudgeDetector]:
        return [
            LLMJudgeDetector(
                spec.judge_fn,
                name=spec.name,
                plane=spec.plane,
                signal_type=spec.signal_type,
                tier=self.tier,
                samples=spec.samples,
                severity=spec.severity,
                locus=spec.locus,
            )
            for spec in self.specs
        ]
