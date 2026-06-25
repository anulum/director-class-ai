# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — causal takeover detector (action plane, tier 0)

"""Detect when untrusted context becomes the causal source of an action.

Origin taint answers "where did this action come from?". Intent consistency
answers "does this action match the user task?". This detector binds those facts
to the task timeline: user intent, retrieved content, intermediate plan, and
proposed effector action. It fires only when a mutating action is causally traced
to untrusted context while the user intent did not authorise that mutation. The
control response is fail-closed: quarantine the tainted context and block or
escalate through the action governor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)
from ._lexicon import IRREVERSIBLE, MUTATING, MUTATING_TASK, UNTRUSTED_ORIGINS

__all__ = ["CAUSAL_TIMELINE_KEY", "ActionTimeline", "CausalTakeoverDetector"]

CAUSAL_TIMELINE_KEY = "causal_timeline"
_CATASTROPHIC_ACTION = re.compile(
    r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)\s+(?:/|/\*)\b"
    r"|\bdrop\s+(?:database|schema|table)\b"
    r"|\bmkfs(?:\.\w+)?\b"
    r"|\bdd\b.*\bof=/dev/",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ActionTimeline:
    """Minimal task timeline used to detect injection-to-effector causality."""

    user_intent: str = ""
    retrieved_content: str = ""
    intermediate_plan: str = ""
    proposed_action: str = ""
    action_source: str = ""

    @classmethod
    def from_mapping(cls, value: dict[str, object]) -> ActionTimeline:
        """Build a timeline from metadata while rejecting non-string payloads."""
        return cls(
            user_intent=_string(value.get("user_intent")),
            retrieved_content=_string(value.get("retrieved_content")),
            intermediate_plan=_string(value.get("intermediate_plan")),
            proposed_action=_string(value.get("proposed_action")),
            action_source=_string(value.get("action_source")),
        )

    def to_metadata(self) -> dict[str, str]:
        """Return the JSON-serialisable benchmark / audit representation."""
        return {
            "user_intent": self.user_intent,
            "retrieved_content": self.retrieved_content,
            "intermediate_plan": self.intermediate_plan,
            "proposed_action": self.proposed_action,
            "action_source": self.action_source,
        }


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _timeline_from_request(request: EvaluationRequest) -> ActionTimeline:
    raw = request.metadata.get(CAUSAL_TIMELINE_KEY)
    if isinstance(raw, ActionTimeline):
        return raw
    if isinstance(raw, dict):
        return ActionTimeline.from_mapping(raw)
    return ActionTimeline(
        user_intent=request.query,
        retrieved_content=request.context,
        intermediate_plan="",
        proposed_action=request.action,
        action_source=request.action_provenance,
    )


def _contains_action_source(text: str, action: str) -> bool:
    """Return true when context or plan visibly carries the proposed mutation."""
    haystack = text.casefold()
    needle = action.strip().casefold()
    if needle and needle in haystack:
        return True
    return bool(MUTATING.search(text))


def _severity(action: str, source: str) -> Severity:
    if _CATASTROPHIC_ACTION.search(action) and source in {
        "retrieved",
        "tool_output",
        "web",
    }:
        return Severity.CRITICAL
    if IRREVERSIBLE.search(action):
        return Severity.HIGH
    return Severity.HIGH


class CausalTakeoverDetector:
    """Tier-0 detector for untrusted-context causal control of actions."""

    name = "causal_takeover"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Detect untrusted context that causally drives a mutating action."""
        timeline = _timeline_from_request(request)
        action = (timeline.proposed_action or request.action).strip()
        if not action or not MUTATING.search(action):
            return None

        user_intent = (timeline.user_intent or request.query).strip()
        if MUTATING_TASK.search(user_intent):
            return None

        source = (timeline.action_source or request.action_provenance).strip().lower()
        context = timeline.retrieved_content
        plan = timeline.intermediate_plan
        if source not in UNTRUSTED_ORIGINS:
            return None
        if not _contains_action_source(f"{context}\n{plan}", action):
            return None

        severity = _severity(action, source)
        score = 0.94 if severity is Severity.CRITICAL else 0.86
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=score,
            locus=Locus.ACTION,
            signal_type="causal_takeover",
            severity=severity,
            rationale=(
                f"untrusted {source!r} context became the causal source of a "
                "state-changing action; quarantine tainted context before review"
            ),
        )
