# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — Python tool-call middleware

"""Python SDK middleware for reviewing tool calls before execution.

The middleware is the package-level integration point for applications that do
not speak MCP directly. A caller submits a typed tool-call request, the existing
Governor reviews the rendered action through the same action-plane detectors as
the lower-level effectors, and an injected executor is called only after a permit
decision and only when ``dry_run`` is disabled. Audit events expose digests,
routes, detector firings, and argument keys, never raw argument values or raw
outputs.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from ..action import (
    BlastRadiusDetector,
    BrowserActionDetector,
    CausalTakeoverDetector,
    DestructiveCommandDetector,
    IntentConsistencyDetector,
    MemoryThreatDetector,
    OriginTaintDetector,
    ReversibilityDetector,
)
from ..action._lexicon import UNTRUSTED_ORIGINS
from ..core import Decision, Detector, EvaluationRequest, Governor, ParallelEnsembleScorer
from ..core.fusion import FusionPolicy
from ..core.governor import ApprovalHook, AuditSink

__all__ = [
    "ToolExecutionResult",
    "ToolExecutor",
    "ToolMiddlewareDecision",
    "ToolReviewMiddleware",
    "ToolReviewRequest",
]

ToolRoute = Literal["allow", "block", "human"]


@dataclass(frozen=True)
class ToolExecutionResult:
    """Digest-only execution result returned by an injected tool executor."""

    output: object = ""
    exit_code: int = 0

    @property
    def output_digest(self) -> str:
        """Return a stable digest for the output without exposing raw content."""
        return _digest(self.output)

    @property
    def output_size(self) -> int:
        """Return the UTF-8 byte size of the rendered output."""
        return len(_canonical(self.output).encode("utf-8"))


ToolExecutor = Callable[["ToolReviewRequest"], ToolExecutionResult]


@dataclass(frozen=True)
class ToolReviewRequest:
    """A generic Python tool-call request crossing the action boundary."""

    tool_name: str
    arguments: Mapping[str, object] = field(default_factory=dict)
    action: str = ""
    provenance: str = ""
    query: str = ""
    context: str = ""
    tenant_id: str = ""
    dry_run: bool = True
    argument_provenance: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, object] = field(default_factory=dict)

    def rendered_action(self) -> str:
        """Render the tool call for action-plane detectors."""
        if self.action.strip():
            return self.action
        lines = [self.tool_name]
        for key in sorted(self.arguments):
            lines.append(f"{key}={_canonical(self.arguments[key])}")
        return "\n".join(lines)

    def to_evaluation(self) -> EvaluationRequest:
        """Build the shared Governor request for this tool call."""
        return EvaluationRequest(
            query=self.query,
            context=self.context,
            action=self.rendered_action(),
            action_provenance=self.provenance,
            tenant_id=self.tenant_id,
            metadata={
                **dict(self.metadata),
                "dry_run": self.dry_run,
                "tool_name": self.tool_name,
                "argument_keys": tuple(sorted(self.arguments)),
                "argument_provenance": dict(self.argument_provenance),
            },
        )

    def tainted_argument_keys(self) -> tuple[str, ...]:
        """Return argument names whose provenance is an untrusted channel."""
        return tuple(
            sorted(
                key
                for key, provenance in self.argument_provenance.items()
                if provenance.strip().lower() in UNTRUSTED_ORIGINS
            )
        )


@dataclass(frozen=True)
class ToolMiddlewareDecision:
    """Middleware decision plus redacted execution and audit metadata."""

    request: ToolReviewRequest = field(repr=False, compare=False)
    decision: Decision
    route: ToolRoute
    permitted: bool
    escalated: bool
    executed: bool
    risk: float
    requires_human: bool
    firing: tuple[str, ...]
    request_digest: str
    action_digest: str
    output_digest: str = ""
    output_size: int = 0
    exit_code: int | None = None

    @classmethod
    def from_governor(
        cls,
        request: ToolReviewRequest,
        decision: Decision,
        *,
        execution: ToolExecutionResult | None = None,
    ) -> ToolMiddlewareDecision:
        """Build a middleware decision from a Governor decision."""
        executed = execution is not None
        return cls(
            request=request,
            decision=decision,
            route=_route(permitted=decision.permitted, escalated=decision.escalated),
            permitted=decision.permitted,
            escalated=decision.escalated,
            executed=executed,
            risk=decision.verdict.risk,
            requires_human=decision.verdict.requires_human,
            firing=decision.record.firing,
            request_digest=decision.record.request_digest,
            action_digest=_digest(request.rendered_action()),
            output_digest=execution.output_digest if execution else "",
            output_size=execution.output_size if execution else 0,
            exit_code=execution.exit_code if execution else None,
        )

    def to_audit_event(self) -> dict[str, object]:
        """Return a privacy-safe audit event for SDK middleware callers."""
        return {
            "event_type": "tool_middleware_decision",
            "tool_name": self.request.tool_name,
            "route": self.route,
            "permitted": self.permitted,
            "escalated": self.escalated,
            "executed": self.executed,
            "risk": self.risk,
            "requires_human": self.requires_human,
            "firing": self.firing,
            "request_digest": self.request_digest,
            "action_digest": self.action_digest,
            "argument_keys": tuple(sorted(self.request.arguments)),
            "argument_count": len(self.request.arguments),
            "tainted_argument_keys": self.request.tainted_argument_keys(),
            "metadata_keys": tuple(sorted(self.request.metadata)),
            "output_digest": self.output_digest,
            "output_size": self.output_size,
            "exit_code": self.exit_code,
        }


class ToolReviewMiddleware:
    """Governor-backed Python middleware for arbitrary tool-call review."""

    def __init__(
        self,
        governor: Governor,
        *,
        executor: ToolExecutor | None = None,
    ) -> None:
        self._governor = governor
        self._executor = executor

    @classmethod
    def default(
        cls,
        *,
        detectors: Sequence[Detector] | None = None,
        policy: FusionPolicy | None = None,
        approval: ApprovalHook | None = None,
        audit_sink: AuditSink | None = None,
        executor: ToolExecutor | None = None,
    ) -> ToolReviewMiddleware:
        """Build middleware with the default action-plane detector ensemble.

        ``policy`` is the fused governance posture in force. Passing the approved
        head of a Guardrail-as-Code ledger (``Profile.to_fusion_policy()``) is how
        an approved posture change actually governs runtime decisions; ``None``
        keeps the fail-closed default thresholds.
        """
        ensemble = ParallelEnsembleScorer(
            tuple(detectors or _default_detectors()), policy=policy
        )
        governor = Governor(
            ensemble=ensemble,
            approval=approval,
            audit_sink=audit_sink,
        )
        return cls(governor, executor=executor)

    def review(self, request: ToolReviewRequest) -> ToolMiddlewareDecision:
        """Review a tool call without dispatching the underlying tool."""
        decision = self._governor.review(request.to_evaluation())
        return ToolMiddlewareDecision.from_governor(request, decision)

    def run(
        self,
        request: ToolReviewRequest,
        *,
        executor: ToolExecutor | None = None,
    ) -> ToolMiddlewareDecision:
        """Review and optionally execute one tool call after a permit decision."""
        decision = self._governor.review(request.to_evaluation())
        runner = executor or self._executor
        if not decision.permitted or request.dry_run or runner is None:
            return ToolMiddlewareDecision.from_governor(request, decision)
        return ToolMiddlewareDecision.from_governor(
            request,
            decision,
            execution=runner(request),
        )


def _default_detectors() -> tuple[Detector, ...]:
    return (
        DestructiveCommandDetector(),
        BlastRadiusDetector(),
        OriginTaintDetector(),
        IntentConsistencyDetector(),
        CausalTakeoverDetector(),
        ReversibilityDetector(),
        BrowserActionDetector(),
        MemoryThreatDetector(),
    )


def _route(*, permitted: bool, escalated: bool) -> ToolRoute:
    if escalated:
        return "human"
    if permitted:
        return "allow"
    return "block"


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()[:16]
