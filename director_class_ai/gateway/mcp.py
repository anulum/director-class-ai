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
import re
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
    "MCPDiscoveryDecision",
    "MCPDiscoveryRequest",
    "MCPGateway",
    "MCPGatewayDecision",
    "MCPGatewayRequest",
    "MCPGatewayRoute",
    "MCPResponseDecision",
    "MCPResponseRequest",
    "MCPToolDescriptor",
]

MCPGatewayRoute = Literal["allow", "block", "human"]

_TRANSPORTS = frozenset({"stdio", "http", "https", "sse", "websocket"})
_DISCOVERY_POISONING = re.compile(
    r"\b("
    r"ignore\s+(?:all\s+)?previous\s+instructions|"
    r"system\s+prompt|"
    r"developer\s+message|"
    r"always\s+(?:choose|use|call)|"
    r"prefer\s+this\s+tool|"
    r"exfiltrat(?:e|ion)|"
    r"send\s+(?:secrets?|credentials?)|"
    r"hidden\s+instruction"
    r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class MCPToolDescriptor:
    """One MCP tool descriptor received during discovery."""

    server: str
    tool: str
    description: str = ""
    input_schema: Mapping[str, object] = field(default_factory=dict)
    output_schema: Mapping[str, object] = field(default_factory=dict)
    argument_schema: Mapping[str, object] = field(default_factory=dict)
    server_identity: Mapping[str, object] = field(default_factory=dict)
    transport: str = "stdio"
    hidden_metadata: Mapping[str, object] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        return _digest(
            {
                "server": self.server,
                "tool": self.tool,
                "description": self.description,
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
                "argument_schema": self.argument_schema,
                "server_identity": self.server_identity,
                "transport": self.transport,
                "hidden_metadata": self.hidden_metadata,
            }
        )

    def to_registration(self) -> MCPToolRegistration:
        return MCPToolRegistration(
            server=self.server,
            tool=self.tool,
            server_identity=self.server_identity,
            tool_schema={
                "description": self.description,
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
                "transport": self.transport,
            },
            argument_schema=self.argument_schema,
        )


@dataclass(frozen=True)
class MCPDiscoveryRequest:
    """Tool-discovery envelope for a server's advertised MCP capabilities."""

    server: str
    descriptors: tuple[MCPToolDescriptor, ...]
    provenance: str = ""
    tenant_id: str = ""

    @classmethod
    def from_descriptors(
        cls,
        server: str,
        descriptors: Sequence[MCPToolDescriptor],
        *,
        provenance: str = "",
        tenant_id: str = "",
    ) -> MCPDiscoveryRequest:
        return cls(
            server=server,
            descriptors=tuple(descriptors),
            provenance=provenance,
            tenant_id=tenant_id,
        )


@dataclass(frozen=True)
class MCPDiscoveryDecision:
    """Fail-closed decision over discovered MCP descriptors."""

    request: MCPDiscoveryRequest
    route: MCPGatewayRoute
    permitted: bool
    findings: tuple[str, ...]
    descriptor_digests: tuple[str, ...]

    def registrations(self) -> tuple[MCPToolRegistration, ...]:
        if not self.permitted:
            return ()
        return tuple(
            descriptor.to_registration() for descriptor in self.request.descriptors
        )

    def to_audit_event(self) -> dict[str, object]:
        return {
            "event_type": "mcp_discovery_decision",
            "server": self.request.server,
            "route": self.route,
            "permitted": self.permitted,
            "findings": self.findings,
            "tool_count": len(self.request.descriptors),
            "tools": tuple(descriptor.tool for descriptor in self.request.descriptors),
            "descriptor_digests": self.descriptor_digests,
            "tenant_id": self.request.tenant_id,
        }


@dataclass(frozen=True)
class MCPResponseRequest:
    """Tool-response envelope for post-call response handling."""

    call: MCPToolCall
    output: object = ""
    content_type: str = "text/plain"
    error: bool = False
    provenance: str = "tool_output"
    tenant_id: str = ""
    metadata: Mapping[str, object] = field(default_factory=dict)

    @property
    def rendered_output(self) -> str:
        if isinstance(self.output, str):
            return self.output
        return _canonical(self.output)

    def to_evaluation(self) -> EvaluationRequest:
        return EvaluationRequest(
            response=self.rendered_output,
            action=self.rendered_output,
            action_provenance="",
            tenant_id=self.tenant_id,
            metadata={MCP_CALL_KEY: self.call, "mcp_response_error": self.error},
        )


@dataclass(frozen=True)
class MCPResponseDecision:
    """Governor-backed response handling decision with redacted audit metadata."""

    request: MCPResponseRequest = field(repr=False, compare=False)
    decision: Decision
    route: MCPGatewayRoute
    permitted: bool
    escalated: bool
    risk: float
    requires_human: bool
    firing: tuple[str, ...]
    request_digest: str
    response_digest: str
    response_size: int

    @classmethod
    def from_governor(
        cls,
        request: MCPResponseRequest,
        decision: Decision,
    ) -> MCPResponseDecision:
        return cls(
            request=request,
            decision=decision,
            route=_route(permitted=decision.permitted, escalated=decision.escalated),
            permitted=decision.permitted,
            escalated=decision.escalated,
            risk=decision.verdict.risk,
            requires_human=decision.verdict.requires_human,
            firing=decision.record.firing,
            request_digest=decision.record.request_digest,
            response_digest=_digest(request.rendered_output),
            response_size=len(request.rendered_output.encode("utf-8")),
        )

    def to_audit_event(self) -> dict[str, object]:
        return {
            "event_type": "mcp_response_decision",
            "server": self.request.call.server,
            "tool": self.request.call.tool,
            "route": self.route,
            "permitted": self.permitted,
            "escalated": self.escalated,
            "risk": self.risk,
            "requires_human": self.requires_human,
            "firing": self.firing,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "response_size": self.response_size,
            "content_type": self.request.content_type,
            "error": self.request.error,
            "metadata_keys": tuple(sorted(self.request.metadata)),
        }


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


def _normalise_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _discovery_text(descriptor: MCPToolDescriptor) -> str:
    return "\n".join(
        (
            descriptor.description,
            _canonical(descriptor.input_schema),
            _canonical(descriptor.output_schema),
            _canonical(descriptor.argument_schema),
            _canonical(descriptor.hidden_metadata),
        )
    )


def _review_discovery(request: MCPDiscoveryRequest) -> tuple[str, ...]:
    findings: list[str] = []
    if not request.server.strip():
        findings.append("missing_server")
    if not request.descriptors:
        findings.append("empty_discovery")

    seen_exact: set[tuple[str, str]] = set()
    seen_normalised: dict[tuple[str, str], str] = {}
    for descriptor in request.descriptors:
        if descriptor.server != request.server:
            findings.append("server_mismatch")
        if not descriptor.tool.strip():
            findings.append("missing_tool")
        transport = descriptor.transport.strip().lower()
        if transport not in _TRANSPORTS:
            findings.append("unsupported_transport")
        exact = (descriptor.server, descriptor.tool)
        if exact in seen_exact:
            findings.append("duplicate_tool_descriptor")
        seen_exact.add(exact)

        normalised = (descriptor.server, _normalise_name(descriptor.tool))
        previous = seen_normalised.get(normalised)
        if previous is not None and previous != descriptor.tool:
            findings.append("tool_name_collision")
        seen_normalised[normalised] = descriptor.tool

        if _DISCOVERY_POISONING.search(_discovery_text(descriptor)):
            findings.append("discovery_poisoning")

    return tuple(dict.fromkeys(findings))


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
    """Review MCP discovery, tool calls, and tool responses."""

    def __init__(
        self,
        governor: Governor,
        *,
        response_governor: Governor | None = None,
    ) -> None:
        self._governor = governor
        self._response_governor = response_governor or Governor(
            ensemble=ParallelEnsembleScorer(
                [DestructiveCommandDetector(), BlastRadiusDetector()]
            )
        )

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
        call_governor = Governor(
            ensemble=ensemble,
            approval=approval,
            audit_sink=audit_sink,
        )
        response_governor = Governor(
            ensemble=ParallelEnsembleScorer(
                [DestructiveCommandDetector(), BlastRadiusDetector()]
            ),
            approval=approval,
            audit_sink=audit_sink,
        )
        return cls(
            call_governor,
            response_governor=response_governor,
        )

    def review_discovery(self, request: MCPDiscoveryRequest) -> MCPDiscoveryDecision:
        """Review a discovery envelope before trusting advertised tools."""

        findings = _review_discovery(request)
        permitted = not findings
        return MCPDiscoveryDecision(
            request=request,
            route=_route(permitted=permitted, escalated=False),
            permitted=permitted,
            findings=findings,
            descriptor_digests=tuple(
                descriptor.digest for descriptor in request.descriptors
            ),
        )

    def review_response(self, request: MCPResponseRequest) -> MCPResponseDecision:
        """Review a tool response before it is exposed to later agent steps."""

        decision = self._response_governor.review(request.to_evaluation())
        return MCPResponseDecision.from_governor(request, decision)

    def review(self, request: MCPGatewayRequest) -> MCPGatewayDecision:
        """Review a typed MCP request without executing the tool."""

        decision = self._governor.review(request.to_evaluation())
        return MCPGatewayDecision.from_governor(request.call, decision)
