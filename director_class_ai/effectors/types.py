# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — effector boundary types

"""The typed boundary an autonomous agent's action must cross to reach an effector.

The Governor returns a verdict; these types make it the *unavoidable* pre-execution
choke point. An :class:`EffectorRequest` describes the concrete operation (a shell
command, SQL statement, HTTP call, MCP tool call); a :class:`GovernedEffector`
reviews it through the Governor and only then — if permitted and not a dry run —
invokes the injected execution function. The execution side is always injected, so
the boundary logic is testable without ever touching a real shell or database, and
**dry-run is the default**: nothing executes until a deployment explicitly opts in.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.governor import Decision, Governor
from ..core.signal import EvaluationRequest

__all__ = [
    "EffectorKind",
    "EffectorRequest",
    "EffectorResult",
    "GovernedEffector",
    "ReversibilityMetadata",
]


class EffectorKind(enum.Enum):
    """The class of real-world effector an action targets."""

    SHELL = "shell"
    SQL = "sql"
    HTTP = "http"
    MCP = "mcp"
    INFRA = "infra"
    CUSTOM = "custom"


@dataclass(frozen=True)
class ReversibilityMetadata:
    """Rollback evidence for mutations, carrying digests instead of raw artefacts."""

    snapshot_id: str = ""
    rollback_command: str = ""
    transaction_id: str = ""
    dry_run_digest: str = ""
    diff_digest: str = ""

    def to_metadata(self) -> dict[str, str]:
        """Return digest-only reversibility metadata for detector review."""
        return {
            "snapshot_id": self.snapshot_id,
            "rollback_command": self.rollback_command,
            "transaction_id": self.transaction_id,
            "dry_run_digest": self.dry_run_digest,
            "diff_digest": self.diff_digest,
        }


@dataclass(frozen=True)
class EffectorRequest:
    """A concrete operation an agent proposes to run against an effector."""

    action: str
    kind: EffectorKind = EffectorKind.SHELL
    provenance: str = ""  # user | untrusted | retrieved | tool_output | ""
    query: str = ""  # the task the agent was given, for intent checks
    context: str = ""
    tenant_id: str = ""
    dry_run: bool = True  # default: never execute unless explicitly opted in
    metadata: dict[str, object] = field(default_factory=dict)
    reversibility: ReversibilityMetadata = field(default_factory=ReversibilityMetadata)

    def to_evaluation(self) -> EvaluationRequest:
        """Convert the effector request into the shared detector input shape."""
        metadata = dict(self.metadata)
        reversibility = self.reversibility.to_metadata()
        if any(reversibility.values()):
            metadata["reversibility"] = reversibility
        return EvaluationRequest(
            query=self.query,
            context=self.context,
            action=self.action,
            action_provenance=self.provenance,
            tenant_id=self.tenant_id,
            metadata=metadata,
        )


@dataclass(frozen=True)
class EffectorResult:
    """The outcome of taking an EffectorRequest through the boundary."""

    permitted: bool
    executed: bool
    decision: Decision
    output_digest: str = ""  # digest of execution output — never raw stdout/stderr
    exit_code: int | None = None

    @property
    def decision_id(self) -> str:
        """Return the request digest that identifies the governance decision."""
        return self.decision.record.request_digest


# An execution function turns an action into (output_text, exit_code). It is only
# ever called for a permitted, non-dry-run request.
ExecuteFn = Callable[[str], tuple[str, int]]


class GovernedEffector:
    """Run effector requests through the Governor — fail-closed, dry-run default."""

    kind: EffectorKind = EffectorKind.CUSTOM

    def __init__(
        self,
        governor: Governor,
        execute: ExecuteFn | None = None,
    ) -> None:
        self._governor = governor
        self._execute = execute

    def run(self, request: EffectorRequest) -> EffectorResult:
        """Govern and optionally execute one effector request."""
        decision = self._governor.review(request.to_evaluation())
        # blocked, dry-run, or no executor wired -> never touch the effector
        if not decision.permitted or request.dry_run or self._execute is None:
            return EffectorResult(
                permitted=decision.permitted, executed=False, decision=decision
            )
        output, exit_code = self._execute(request.action)
        return _executed_result(decision, output, exit_code)


def _executed_result(decision: Decision, output: str, exit_code: int) -> EffectorResult:
    """Build the result of a permitted, real (non-dry-run) execution."""
    return EffectorResult(
        permitted=True,
        executed=True,
        decision=decision,
        output_digest=_digest(output),
        exit_code=exit_code,
    )


def _digest(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
