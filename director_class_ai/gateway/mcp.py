# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP gateway contract

"""In-process MCP gateway contract.

The gateway is a deployable boundary around the existing MCP trust registry,
structured inspector, serialised action detectors, and Governor. It deliberately
does not dispatch tools. Callers submit a typed request, receive a typed
decision, and can emit a privacy-safe audit event that binds to the governed call
without carrying raw argument values.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from ..action import (
    MCP_CALL_KEY,
    BlastRadiusDetector,
    DestructiveCommandDetector,
    MCPCallInspector,
    MCPToolCall,
    MCPToolRegistration,
    MCPTrustRegistry,
    OriginTaintDetector,
    serialise_call,
)
from ..core import Decision, EvaluationRequest, Governor, ParallelEnsembleScorer
from ..core.governor import ApprovalHook, AuditSink

__all__ = [
    "MCPGateway",
    "MCPGatewayDecision",
    "MCPGatewayRequest",
    "MCPGatewayRoute",
]

MCPGatewayRoute = Literal["allow", "block", "human"]


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()[:16]


def _schema_digest(call: MCPToolCall) -> str:
    return _digest(
        {
            "server_identity": call.server_identity,
            "tool_schema": call.tool_schema,
            "argument_schema": call.argument_schema,
        }
    )


def _call_digest(call: MCPToolCall) -> str:
    return _digest(
        {
            "server": call.server,
            "tool": call.tool,
            "arguments": call.arguments,
            "arg_provenance": call.arg_provenance,
            "default_provenance": call.default_provenance,
            "server_identity": call.server_identity,
            "tool_schema": call.tool_schema,
            "argument_schema": call.argument_schema,
        }
    )


def _route(*, permitted: bool, escalated: bool) -> MCPGatewayRoute:
    if escalated:
        return "human"
    if permitted:
        return "allow"
    return "block"


@dataclass(frozen=True)
class MCPGatewayRequest:
    """A typed MCP tool-call review request.

    ``dry_run`` is carried for service/proxy callers that want a uniform request
    shape with the effector adapters. The gateway itself reviews only; execution
    remains the responsibility of an explicit effector after a permit decision.
    """

    call: MCPToolCall
    provenance: str = ""
    query: str = ""
    context: str = ""
    tenant_id: str = ""
    dry_run: bool = True

    @classmethod
    def from_parts(
        cls,
        server: str,
        tool: str,
        arguments: Mapping[str, object] | None = None,
        *,
        arg_provenance: Mapping[str, str] | None = None,
        default_provenance: str = "",
        server_identity: Mapping[str, object] | None = None,
        tool_schema: Mapping[str, object] | None = None,
        argument_schema: Mapping[str, object] | None = None,
        provenance: str = "",
        query: str = "",
        context: str = "",
        tenant_id: str = "",
        dry_run: bool = True,
    ) -> MCPGatewayRequest:
        call = MCPToolCall(
            server=server,
            tool=tool,
            arguments=dict(arguments or {}),
            arg_provenance=dict(arg_provenance or {}),
            default_provenance=default_provenance or provenance,
            server_identity=dict(server_identity or {}),
            tool_schema=dict(tool_schema or {}),
            argument_schema=dict(argument_schema or {}),
        )
        return cls(
            call=call,
            provenance=provenance or default_provenance,
            query=query,
            context=context,
            tenant_id=tenant_id,
            dry_run=dry_run,
        )

    def to_evaluation(self) -> EvaluationRequest:
        """Build the Governor request with both MCP inspection paths preserved."""

        return EvaluationRequest(
            query=self.query,
            context=self.context,
            action=serialise_call(self.call),
            action_provenance=self.provenance,
            tenant_id=self.tenant_id,
            metadata={MCP_CALL_KEY: self.call, "dry_run": self.dry_run},
        )


@dataclass(frozen=True)
class MCPGatewayDecision:
    """Typed MCP gateway decision plus privacy-safe audit projection."""

    decision: Decision
    call: MCPToolCall = field(repr=False, compare=False)
    call_digest: str
    schema_digest: str
    route: MCPGatewayRoute
    permitted: bool
    escalated: bool
    risk: float
    requires_human: bool
    firing: tuple[str, ...]
    request_digest: str

    @classmethod
    def from_governor(cls, call: MCPToolCall, decision: Decision) -> MCPGatewayDecision:
        permitted = decision.permitted
        escalated = decision.escalated
        return cls(
            decision=decision,
            call=call,
            call_digest=_call_digest(call),
            schema_digest=_schema_digest(call),
            route=_route(permitted=permitted, escalated=escalated),
            permitted=permitted,
            escalated=escalated,
            risk=decision.verdict.risk,
            requires_human=decision.verdict.requires_human,
            firing=decision.record.firing,
            request_digest=decision.record.request_digest,
        )

    def to_audit_event(self) -> dict[str, object]:
        """Return a SIEM-safe event: identifiers and keys, never raw values."""

        return {
            "event_type": "mcp_gateway_decision",
            "server": self.call.server,
            "tool": self.call.tool,
            "route": self.route,
            "permitted": self.permitted,
            "escalated": self.escalated,
            "risk": self.risk,
            "requires_human": self.requires_human,
            "firing": self.firing,
            "request_digest": self.request_digest,
            "call_digest": self.call_digest,
            "schema_digest": self.schema_digest,
            "argument_keys": tuple(sorted(self.call.arguments)),
            "argument_count": len(self.call.arguments),
            "tainted_argument_keys": tuple(
                sorted(key for key in self.call.arguments if self.call.is_tainted(key))
            ),
        }


class MCPGateway:
    """Review MCP tool calls through the Director-Class AI action Governor."""

    def __init__(self, governor: Governor) -> None:
        self._governor = governor

    @classmethod
    def from_registry(
        cls,
        registrations: Sequence[MCPToolRegistration],
        *,
        allow_dynamic_discovery: bool = False,
        approval: ApprovalHook | None = None,
        audit_sink: AuditSink | None = None,
    ) -> MCPGateway:
        """Create a default MCP action gateway from known-good registrations."""

        registry = MCPTrustRegistry(
            registrations,
            allow_dynamic_discovery=allow_dynamic_discovery,
        )
        ensemble = ParallelEnsembleScorer(
            [
                MCPCallInspector(registry=registry),
                DestructiveCommandDetector(),
                BlastRadiusDetector(),
                OriginTaintDetector(),
            ]
        )
        return cls(
            Governor(
                ensemble=ensemble,
                approval=approval,
                audit_sink=audit_sink,
            )
        )

    def review(self, request: MCPGatewayRequest) -> MCPGatewayDecision:
        """Review a typed MCP request without executing the tool."""

        decision = self._governor.review(request.to_evaluation())
        return MCPGatewayDecision.from_governor(request.call, decision)
