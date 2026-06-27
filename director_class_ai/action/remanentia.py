# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — Remanentia MCP memory governance

"""Remanentia MCP memory read/write governance.

This detector is the DCA-side boundary guard for Remanentia's MCP transport.
Remanentia remains the AGPL memory server; Director-Class AI reviews the
transport-level call and response envelopes before a memory write is accepted or
a recalled memory is exposed to later agent context.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from ..core.signal import DetectorSignal, EvaluationRequest, Locus, Plane, Severity
from .mcp_inspector import MCP_CALL_KEY, MCPToolCall
from .memory import (
    MEMORY_CONTEXT_KEY,
    MemoryActionContext,
    MemoryPlanDelta,
    MemoryThreatDetector,
    MemoryWriteContract,
)

__all__ = [
    "REMANENTIA_MEMORY_CONTEXT_KEY",
    "RemanentiaMemoryGovernanceDetector",
    "RemanentiaMemoryOperation",
]

REMANENTIA_MEMORY_CONTEXT_KEY = "remanentia_memory_context"

_READ_TOOLS = frozenset(
    {
        "remanentia_recall",
        "remanentia_graph",
        "recall",
        "search",
        "graph",
    }
)
_WRITE_TOOLS = frozenset(
    {
        "remanentia_remember",
        "remanentia_consolidate",
        "remember",
        "store",
        "consolidate",
    }
)
_LABEL_TOOLS = frozenset(
    {
        "remanentia_recall_feedback",
        "remanentia_recall_correctness",
        "recall_feedback",
        "recall_correctness",
    }
)
_HIGH_IMPACT_SCOPES = frozenset(
    {"global", "identity", "system", "fleet", "tenant", "org", "organization"}
)
_HIGH_IMPACT_TYPES = frozenset(
    {"policy", "approval", "identity", "credential", "safety", "security", "trigger"}
)
_SECRET_VALUE = re.compile(
    r"(?i)("
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|"
    r"\b(?:ghp|github_pat|glpat|sk|xox[baprs])-[-_A-Za-z0-9]{16,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret)"
    r"\s*[:=]\s*['\"]?[-_A-Za-z0-9]{12,}"
    r")"
)
_HIGH_IMPACT_TEXT = re.compile(
    r"\b(system prompt|developer message|approval policy|safety policy|"
    r"identity layer|operator credential|api key|access token|private key|"
    r"always remember|prospective trigger)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RemanentiaMemoryOperation:
    """Classified Remanentia MCP memory operation."""

    kind: str
    tool: str
    arguments: Mapping[str, object]

    @property
    def is_read(self) -> bool:
        """Return whether this operation reads memory into agent context."""
        return self.kind == "read"

    @property
    def is_write(self) -> bool:
        """Return whether this operation persists memory content."""
        return self.kind == "write"

    @property
    def is_label_mutation(self) -> bool:
        """Return whether this operation mutates recall-quality labels."""
        return self.kind == "label"


class RemanentiaMemoryGovernanceDetector:
    """Govern Remanentia MCP memory writes and recalled-memory responses."""

    name = "remanentia_memory_governance"
    plane = Plane.ACTION
    tier = 0

    def __init__(
        self,
        memory_detector: MemoryThreatDetector | None = None,
    ) -> None:
        self._memory_detector = memory_detector or MemoryThreatDetector()

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Return a signal for unsafe Remanentia MCP memory traffic."""
        call = request.metadata.get(MCP_CALL_KEY)
        if not isinstance(call, MCPToolCall) or not _is_remanentia_call(call):
            return None

        operation = _operation(call)
        if operation is None:
            return None

        if operation.is_write:
            memory_signal = self._evaluate_memory_write(request, call)
            if memory_signal is not None:
                return memory_signal
            if _high_impact_memory_mutation(call):
                return _signal(
                    "remanentia_memory_mutation_approval",
                    0.42,
                    Severity.HIGH,
                    "high-impact Remanentia memory mutation requires approval",
                )

        if operation.is_label_mutation and _high_impact_label_mutation(call):
            return _signal(
                "remanentia_memory_mutation_approval",
                0.42,
                Severity.HIGH,
                "Remanentia recall-quality label mutation requires approval",
            )

        if operation.is_read and _secret_leakage(request.response or request.action):
            return _signal(
                "memory_secret_leakage",
                0.95,
                Severity.HIGH,
                "Remanentia recall response contains secret-shaped material",
            )

        return None

    def _evaluate_memory_write(
        self,
        request: EvaluationRequest,
        call: MCPToolCall,
    ) -> DetectorSignal | None:
        context = _memory_context_from_request(request, call)
        evaluation = EvaluationRequest(
            query=request.query,
            response=request.response,
            context=request.context,
            action=request.action,
            action_provenance=request.action_provenance,
            tenant_id=request.tenant_id,
            metadata={MEMORY_CONTEXT_KEY: context.as_metadata()},
        )
        return self._memory_detector.evaluate(evaluation)


def _is_remanentia_call(call: MCPToolCall) -> bool:
    server = _normalise(call.server)
    tool = _normalise(call.tool)
    identity_name = _normalise(call.server_identity.get("name"))
    return (
        server == "remanentia"
        or identity_name == "remanentia"
        or tool.startswith("remanentia_")
    )


def _operation(call: MCPToolCall) -> RemanentiaMemoryOperation | None:
    tool = _normalise(call.tool)
    if tool in _WRITE_TOOLS:
        kind = "write"
    elif tool in _LABEL_TOOLS:
        kind = "label"
    elif tool in _READ_TOOLS:
        kind = "read"
    else:
        return None
    return RemanentiaMemoryOperation(kind, tool, call.arguments)


def _memory_context_from_request(
    request: EvaluationRequest,
    call: MCPToolCall,
) -> MemoryActionContext:
    explicit = request.metadata.get(REMANENTIA_MEMORY_CONTEXT_KEY)
    if isinstance(explicit, MemoryActionContext):
        return explicit
    if isinstance(explicit, Mapping):
        return MemoryActionContext.from_mapping(explicit)

    args = call.arguments
    contract = _contract(args)
    project = _string(args.get("project"))
    memory_type = _string(args.get("type") or args.get("memory_type"))
    retrieval_context = _string(
        args.get("retrieval_context") or project or memory_type or "remanentia"
    )
    plan_delta = _plan_delta(request, args)
    return MemoryActionContext(
        tenant=_string(args.get("tenant") or request.tenant_id),
        retrieval_context=retrieval_context,
        now=_integer(args.get("now")),
        contract=contract,
        plan_delta=plan_delta,
        cached_schema_digest=_string(args.get("cached_schema_digest")),
        live_schema_digest=_string(args.get("live_schema_digest")),
        memory_text=_memory_text(args),
        memory_source=_string(args.get("memory_source") or call.default_provenance),
    )


def _contract(args: Mapping[str, object]) -> MemoryWriteContract | None:
    raw = args.get("contract") or args.get("memory_contract")
    if isinstance(raw, MemoryWriteContract):
        return raw
    if isinstance(raw, Mapping):
        return MemoryWriteContract.from_mapping(raw)
    return None


def _plan_delta(
    request: EvaluationRequest,
    args: Mapping[str, object],
) -> MemoryPlanDelta:
    raw = args.get("plan_delta")
    if isinstance(raw, Mapping):
        return MemoryPlanDelta.from_mapping(raw)
    return MemoryPlanDelta(
        user_goal=request.query,
        current_plan=request.context,
        retrieved_context=_string(args.get("retrieved_context")),
        proposed_next_action=request.action,
    )


def _memory_text(args: Mapping[str, object]) -> str:
    return _string(
        args.get("content") or args.get("memory") or args.get("text") or args.get("value")
    )


def _high_impact_memory_mutation(call: MCPToolCall) -> bool:
    args = call.arguments
    scope = _string(args.get("scope")).strip().lower()
    memory_type = _string(args.get("type") or args.get("memory_type")).strip().lower()
    trigger = _string(args.get("trigger"))
    content = _memory_text(args)
    return (
        _normalise(call.tool) in {"remanentia_consolidate", "consolidate"}
        or scope in _HIGH_IMPACT_SCOPES
        or memory_type in _HIGH_IMPACT_TYPES
        or bool(trigger.strip())
        or bool(_HIGH_IMPACT_TEXT.search(content))
    )


def _high_impact_label_mutation(call: MCPToolCall) -> bool:
    args = call.arguments
    if _string(args.get("was_correct")).strip().lower() == "false":
        return True
    if _string(args.get("was_used")).strip().lower() == "false":
        return True
    return bool(_string(args.get("query")).strip())


def _secret_leakage(text: str) -> bool:
    return bool(_SECRET_VALUE.search(text))


def _signal(
    signal_type: str,
    score: float,
    severity: Severity,
    rationale: str,
) -> DetectorSignal:
    return DetectorSignal(
        detector="remanentia_memory_governance",
        plane=Plane.ACTION,
        score=score,
        locus=Locus.ACTION,
        signal_type=signal_type,
        severity=severity,
        rationale=rationale,
    )


def _normalise(value: object) -> str:
    return _string(value).strip().lower().replace("-", "_")


def _integer(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0


def _string(value: object) -> str:
    return "" if value is None else str(value)
