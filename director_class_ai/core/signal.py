# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — plane-agnostic detector signal and protocol

"""The keystone abstraction every detector and the fusion layer share.

A detector — whether it judges *content* (is this claim grounded?), *integrity*
(was the input manipulated?), or *action* (is this command safe to execute?) —
emits the same :class:`DetectorSignal`. That uniformity is what lets one parallel
ensemble and one calibrated fusion layer govern all three planes at once: the
fusion never needs to know what a detector *is*, only what it *reported* and how
much that detector should be trusted on the thing it reported.

Two design choices carry the product:

* **Plane-agnostic signal.** ``score`` is always "probability this is a problem"
  in ``[0, 1]``; ``locus`` says *where* (input, token, span, claim, response, or a
  concrete action); ``severity`` says *how bad if real*; ``calibration`` says how
  much to trust this detector on this signal type. A destructive-command detector
  and a contradiction NLI both speak this language.
* **Per-plane fusion mode.** Content fuses *fail-open* (allow unless confidently a
  problem — a false halt only annoys). Action fuses *fail-closed* (block unless
  confidently safe — a missed ``rm -rf`` is catastrophic, a false block is a minor
  inconvenience). The loss function is inverted across planes, so the fusion mode
  is a per-plane setting, not a global one.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = [
    "Plane",
    "Locus",
    "Severity",
    "FusionMode",
    "Span",
    "EvaluationRequest",
    "DetectorSignal",
    "Detector",
]


class Plane(enum.Enum):
    """Which axis of governance a detector or verdict concerns."""

    CONTENT = "content"  # is what the system *says* true / grounded?
    INTEGRITY = "integrity"  # was the input / context manipulated?
    ACTION = "action"  # is what the system *does* safe to execute?


class Locus(enum.Enum):
    """Where in the material a signal applies — its granularity."""

    INPUT = "input"
    TOKEN = "token"
    SPAN = "span"
    CLAIM = "claim"
    RESPONSE = "response"
    ACTION = "action"


class Severity(enum.IntEnum):
    """How damaging the flagged problem is *if real* — drives action tiering."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4  # irreversible / catastrophic blast radius


class FusionMode(enum.Enum):
    """How the fusion layer resolves uncertainty for a plane."""

    FAIL_OPEN = "fail_open"  # allow unless confidently a problem (content)
    FAIL_CLOSED = "fail_closed"  # block unless confidently safe (action)


@dataclass(frozen=True)
class Span:
    """A character range a detector flags, with its local score."""

    start: int
    end: int
    score: float


@dataclass(frozen=True)
class EvaluationRequest:
    """The material handed to every detector.

    ``action`` is populated when an autonomous agent is about to invoke an
    effector (a shell command, SQL statement, API call); content/integrity
    detectors ignore it and action detectors key off it. ``action_provenance``
    records where that action originated — ``"user"`` (a human asked for it),
    ``"untrusted"`` / ``"retrieved"`` / ``"tool_output"`` (it came from content the
    model ingested, which is how a prompt injection reaches the effector). An
    empty value means provenance is unknown.
    """

    query: str = ""
    response: str = ""
    context: str = ""
    action: str = ""  # the concrete effector command/payload, if any
    action_provenance: str = ""  # user | untrusted | retrieved | tool_output | ""
    tenant_id: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class DetectorSignal:
    """One detector's report, in the language the fusion layer understands."""

    detector: str
    plane: Plane
    score: float  # P(problem) in [0, 1]
    locus: Locus
    signal_type: str  # e.g. "contradiction", "baseless_span", "destructive_command"
    severity: Severity = Severity.MEDIUM
    calibration: float = 1.0  # trust in this detector on this signal_type, [0, 1]
    spans: tuple[Span, ...] = ()
    rationale: str = ""
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"score must be in [0, 1], got {self.score}")
        if not 0.0 <= self.calibration <= 1.0:
            raise ValueError(f"calibration must be in [0, 1], got {self.calibration}")

    @property
    def weighted_score(self) -> float:
        """Score discounted by how much this detector is trusted here."""
        return self.score * self.calibration


@runtime_checkable
class Detector(Protocol):
    """A unit of judgement on one plane.

    Implementations are deliberately thin: construct expensive models once, then
    answer :meth:`evaluate` cheaply. ``tier`` lets the ensemble run cheap
    detectors first and gate the expensive ones (blast-radius cascading) — a
    lower tier runs earlier.
    """

    name: str
    plane: Plane
    tier: int

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Return a signal, or ``None`` when the detector does not apply."""
        ...
