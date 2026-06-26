# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — A/B posture exposure

"""Replay a request set under two postures and report the decision delta.

Guardrail-as-Code, increment 3c. Before a posture change is approved (the review
gate, increment 3a), an operator needs to see what the candidate posture would
actually decide. :class:`PostureExposure` replays the same detector signals — one
:class:`ExposureCase` per request — through the baseline posture's fusion policy
and the candidate's, classifies each outcome as ``allow`` / ``escalate`` /
``block``, and reports which cases changed and how.

The comparison is deterministic and model-free: it operates on supplied
:class:`~director_class_ai.core.signal.DetectorSignal` sets, so the same corpus
can be replayed offline for any two postures.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..core.fusion import Verdict, fuse
from ..core.signal import DetectorSignal, EvaluationRequest
from .capability import (
    CAPABILITY_CONTEXT_KEY,
    CapabilityGrant,
    CapabilityPolicyDetector,
)
from .profile import Profile

__all__ = [
    "ALLOW",
    "BLOCK",
    "ESCALATE",
    "ExposureCase",
    "ExposureReport",
    "OutcomeChange",
    "PostureExposure",
]

ALLOW = "allow"
ESCALATE = "escalate"
BLOCK = "block"


def _outcome(verdict: Verdict) -> str:
    """Classify a verdict as ``allow``, ``escalate``, or ``block``.

    A verdict routed to a human is ``escalate`` regardless of its allow flag;
    otherwise it is ``allow`` when permitted and ``block`` when not.
    """
    if verdict.requires_human:
        return ESCALATE
    return ALLOW if verdict.allow else BLOCK


@dataclass(frozen=True)
class ExposureCase:
    """One request's detector signals, replayed under two postures.

    Attributes
    ----------
    label : str
        A stable identifier for the case (e.g. a corpus row id).
    signals : tuple of DetectorSignal
        The detector output for the request; fused under each posture's policy.
    provenance : str
        The request's action provenance (``"user"`` gates authorised-destructive
        routing); empty keeps the case fail-closed.
    capability_context : mapping, optional
        Runtime capability facts to replay through the posture's capability
        profile. Empty keeps the case on fusion-only replay.
    capability_grants : tuple of CapabilityGrant
        Runtime grants available for this case when capability replay is active.
    """

    label: str
    signals: tuple[DetectorSignal, ...]
    provenance: str = ""
    capability_context: Mapping[str, object] = field(default_factory=dict)
    capability_grants: tuple[CapabilityGrant, ...] = ()


@dataclass(frozen=True)
class OutcomeChange:
    """How one case's decision differs between the baseline and candidate posture.

    Attributes
    ----------
    label : str
        The case identifier.
    baseline : str
        Outcome under the baseline posture (``allow`` / ``escalate`` / ``block``).
    candidate : str
        Outcome under the candidate posture.
    """

    label: str
    baseline: str
    candidate: str

    @property
    def changed(self) -> bool:
        """Whether the candidate posture decided this case differently."""
        return self.baseline != self.candidate

    @property
    def transition(self) -> str:
        """The ``baseline->candidate`` transition label for this case."""
        return f"{self.baseline}->{self.candidate}"


@dataclass(frozen=True)
class ExposureReport:
    """The decision delta of a candidate posture against the baseline.

    Attributes
    ----------
    outcomes : tuple of OutcomeChange
        One entry per replayed case, in input order.
    """

    outcomes: tuple[OutcomeChange, ...] = field(default_factory=tuple)

    @property
    def changed(self) -> tuple[OutcomeChange, ...]:
        """The cases the candidate posture decided differently."""
        return tuple(o for o in self.outcomes if o.changed)

    @property
    def changed_count(self) -> int:
        """How many cases changed outcome under the candidate posture."""
        return len(self.changed)

    @property
    def transitions(self) -> dict[str, int]:
        """Count of each ``baseline->candidate`` transition among changed cases."""
        return dict(Counter(o.transition for o in self.changed))


class PostureExposure:
    """Replay cases under a baseline and a candidate posture for comparison."""

    def __init__(self, baseline: Profile, candidate: Profile) -> None:
        """Compare ``candidate`` against the currently approved ``baseline``."""
        self._baseline_profile = baseline
        self._candidate_profile = candidate
        self._baseline = baseline.to_fusion_policy()
        self._candidate = candidate.to_fusion_policy()

    def expose(self, cases: Sequence[ExposureCase]) -> ExposureReport:
        """Replay ``cases`` under both postures and report the decision delta.

        Parameters
        ----------
        cases : sequence of ExposureCase
            The request signal sets to replay.

        Returns
        -------
        ExposureReport
            One :class:`OutcomeChange` per case, in input order.
        """
        outcomes = tuple(
            OutcomeChange(
                label=case.label,
                baseline=_outcome(
                    fuse(
                        _signals_for(self._baseline_profile, case),
                        self._baseline,
                        provenance=case.provenance,
                    )
                ),
                candidate=_outcome(
                    fuse(
                        _signals_for(self._candidate_profile, case),
                        self._candidate,
                        provenance=case.provenance,
                    )
                ),
            )
            for case in cases
        )
        return ExposureReport(outcomes=outcomes)


def _signals_for(profile: Profile, case: ExposureCase) -> tuple[DetectorSignal, ...]:
    """Return fusion signals plus the profile's capability-policy signal."""
    if not case.capability_context:
        return case.signals
    policy = profile.to_capability_policy(case.capability_grants)
    signal = CapabilityPolicyDetector(policy).evaluate(
        EvaluationRequest(
            action_provenance=case.provenance,
            metadata={CAPABILITY_CONTEXT_KEY: dict(case.capability_context)},
        )
    )
    return case.signals if signal is None else (*case.signals, signal)
