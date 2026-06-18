# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — prompt injection integrity adapter

"""Integrity-plane adapter for prompt and context injection screening.

Action-plane taint detectors decide whether an injected instruction reached an
effector. This adapter handles the earlier integrity question: did user or
retrieved text itself look like an instruction takeover attempt? It consumes the
Director-AI ``LayeredPromptGuard`` screen surface through a Protocol so tests can
inject deterministic fakes and package imports stay dependency-light.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane, Severity

__all__ = [
    "InjectionPromptDetector",
    "InjectionScreenBackend",
    "InjectionScreenFinding",
    "InjectionScreenResult",
]

InjectionField = Literal["query", "context"]


@runtime_checkable
class InjectionScreenResult(Protocol):
    """Screening result returned by a prompt-injection backend."""

    blocked: bool
    score: float
    stage: str
    reason: str


@runtime_checkable
class InjectionScreenBackend(Protocol):
    """Backend exposing the Director-AI prompt-guard screening contract."""

    def screen(self, text: str) -> InjectionScreenResult:
        """Screen ``text`` for prompt-injection or jailbreak intent."""
        ...


@dataclass(frozen=True)
class InjectionScreenFinding:
    """A redacted finding for one scanned request field."""

    field: InjectionField
    score: float
    stage: str
    reason: str
    blocked: bool


class InjectionPromptDetector:
    """Integrity-plane adapter for query and retrieved-context injection signals."""

    name = "prompt_injection"
    plane = Plane.INTEGRITY
    tier = 0

    def __init__(
        self,
        backend: InjectionScreenBackend,
        *,
        fields: Sequence[InjectionField] = ("query", "context"),
        threshold: float = 0.5,
    ) -> None:
        """Create a prompt-injection adapter.

        Parameters
        ----------
        backend:
            Prompt guard exposing ``screen(text)`` with ``blocked``, ``score``,
            ``stage``, and ``reason`` attributes.
        fields:
            Request fields to screen. Only query and context are supported; action
            injection-to-effector handling lives in the action plane.
        threshold:
            Minimum backend score required to emit a signal when the backend did
            not already hard-block. Values must be in ``[0, 1]``.

        Raises
        ------
        ValueError
            If ``threshold`` is outside ``[0, 1]`` or an unsupported field is
            requested.
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1], got {threshold}")
        invalid = [field for field in fields if field not in ("query", "context")]
        if invalid:
            raise ValueError(f"unsupported injection scan field(s): {invalid!r}")
        self._backend = backend
        self._fields = tuple(fields)
        self._threshold = float(threshold)

    @classmethod
    def from_layered_prompt_guard(
        cls,
        *,
        fields: Sequence[InjectionField] = ("query", "context"),
        threshold: float = 0.5,
    ) -> InjectionPromptDetector:  # pragma: no cover - needs [detectors] extra
        """Load Director-AI's dependency-light layered prompt guard."""
        from director_ai.core.safety.prompt_guard import LayeredPromptGuard

        return cls(LayeredPromptGuard(), fields=fields, threshold=threshold)

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Emit an integrity signal when query or context screening fires."""
        findings = tuple(self._findings(request))
        if not findings:
            return None
        score = max(finding.score for finding in findings)
        severity = Severity.HIGH if any(f.blocked for f in findings) else Severity.MEDIUM
        fields = ", ".join(finding.field for finding in findings)
        stages = ", ".join(
            sorted({finding.stage for finding in findings if finding.stage})
        )
        return DetectorSignal(
            detector=self.name,
            plane=Plane.INTEGRITY,
            score=score,
            locus=Locus.INPUT,
            signal_type="prompt_injection",
            severity=severity,
            rationale=(
                f"injection signal in {fields}; stage(s): {stages or 'score_threshold'}"
            ),
        )

    def _findings(self, request: EvaluationRequest) -> list[InjectionScreenFinding]:
        """Return redacted findings for configured fields."""
        findings: list[InjectionScreenFinding] = []
        for field in self._fields:
            text = self._field_text(request, field).strip()
            if not text:
                continue
            result = self._backend.screen(text)
            score = min(1.0, max(0.0, float(result.score)))
            if not result.blocked and score < self._threshold:
                continue
            findings.append(
                InjectionScreenFinding(
                    field=field,
                    score=score,
                    stage=result.stage,
                    reason=result.reason,
                    blocked=result.blocked,
                )
            )
        return findings

    @staticmethod
    def _field_text(request: EvaluationRequest, field: InjectionField) -> str:
        """Return the requested screenable text field."""
        if field == "context":
            return request.context
        return request.query
