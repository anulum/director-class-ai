# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — effector-boundary governor

"""The mandatory checkpoint between an autonomous agent and the real effector.

The detectors and fusion produce a verdict; the Governor turns that verdict into
a decision *at the boundary* — the single place an action or output must pass
before a shell runs it, a row is deleted, an API is called. It is the piece that
makes the ensemble an actual kill-switch rather than an advisory score.

It is fail-closed by construction:

* a blocked verdict is not permitted;
* a verdict that needs a human is *not permitted on its own* — it is routed to the
  approval hook, and only an explicit human approval permits it. With no approver
  configured, an escalated action stays blocked (awaiting a person), never
  silently allowed;
* every decision emits an immutable audit record (privacy-preserving digest of the
  request, the verdict, and which detectors fired), so a governed system has a
  reviewable trail of what it was about to do and why it was stopped.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from .ensemble import ParallelEnsembleScorer
from .fusion import Verdict
from .signal import EvaluationRequest

__all__ = ["AuditRecord", "Decision", "Governor"]

ApprovalHook = Callable[[Verdict, EvaluationRequest], bool]
AuditSink = Callable[["AuditRecord"], None]


@dataclass(frozen=True)
class AuditRecord:
    """An immutable, privacy-preserving record of one governance decision."""

    permitted: bool
    escalated: bool
    risk: float
    requires_human: bool
    rationale: str
    firing: tuple[str, ...]  # signal types that fired
    request_digest: str  # sha256 prefix of the request — no raw content / PII


@dataclass(frozen=True)
class Decision:
    """The Governor's resolution of a request at the effector boundary."""

    permitted: bool  # may the action / output proceed?
    escalated: bool  # was it routed to a human?
    verdict: Verdict
    record: AuditRecord


def _digest(request: EvaluationRequest) -> str:
    payload = f"{request.action}\x1f{request.response}\x1f{request.context}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class Governor:
    """Resolve each request through the ensemble into a fail-closed decision."""

    ensemble: ParallelEnsembleScorer
    approval: ApprovalHook | None = None
    audit_sink: AuditSink | None = None
    _trail: list[AuditRecord] = field(default_factory=list, init=False, repr=False)

    def review(self, request: EvaluationRequest) -> Decision:
        verdict = self.ensemble.evaluate(request)
        escalated = False
        if not verdict.allow:
            permitted = False
        elif verdict.requires_human:
            escalated = True
            # fail-closed: an escalated decision needs an explicit human yes;
            # with no approver it stays blocked, never silently permitted.
            permitted = bool(self.approval(verdict, request)) if self.approval else False
        else:
            permitted = True

        record = AuditRecord(
            permitted=permitted,
            escalated=escalated,
            risk=verdict.risk,
            requires_human=verdict.requires_human,
            rationale=verdict.rationale,
            firing=tuple(s.signal_type for s in verdict.firing),
            request_digest=_digest(request),
        )
        self._trail.append(record)
        if self.audit_sink is not None:
            self.audit_sink(record)
        return Decision(
            permitted=permitted,
            escalated=escalated,
            verdict=verdict,
            record=record,
        )

    @property
    def trail(self) -> tuple[AuditRecord, ...]:
        """The in-memory audit trail of every decision made so far."""
        return tuple(self._trail)
