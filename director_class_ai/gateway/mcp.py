# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
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
from typing import TYPE_CHECKING, Literal

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
from ..core import (
    Decision,
    Detector,
    EvaluationRequest,
    FusionPolicy,
    Governor,
    ParallelEnsembleScorer,
)
from ..core.governor import ApprovalHook, AuditSink
from ..core.signal import DetectorSignal, Locus, Plane, Severity
from ..policy import (
    CAPABILITY_CONTEXT_KEY,
    CapabilityContext,
    CapabilityPolicy,
)
from ..policy.capability import CapabilityPolicyDetector

if TYPE_CHECKING:
    from pathlib import Path

    from ..policy import CapabilityGrant

__all__ = [
    "MCPDiscoveryDecision",
    "MCPDiscoveryRequest",
    "MCPGateway",
    "MCPGatewayDecision",
    "MCPGatewayRequest",
    "MCPGatewayRoute",
    "MCPRemoteAuthContext",
    "MCPResponseDecision",
    "MCPResponseRequest",
    "MCPToolDescriptor",
]

MCPGatewayRoute = Literal["allow", "block", "human"]

_TRANSPORTS = frozenset({"stdio", "http", "https", "sse", "websocket"})
_REMOTE_TRANSPORTS = frozenset({"http", "https", "sse", "websocket"})
_TRUSTED_TRANSPORT_PROVENANCE = frozenset(
    {"tls_verified", "pinned_certificate", "mtls", "loopback"}
)
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
_PARAMETER_POISONING = re.compile(
    r"(?:^|[_\-.])("
    r"ignore(?:[_\-.]?previous)?(?:[_\-.]?instructions?)?|"
    r"system(?:[_\-.]?prompt|[_\-.]?message)?|"
    r"developer(?:[_\-.]?message)?|"
    r"hidden(?:[_\-.]?instruction)?|"
    r"override(?:[_\-.]?policy)?|"
    r"jailbreak|"
    r"always(?:[_\-.]?(?:use|call|choose))"
    r")(?:$|[_\-.])",
    re.IGNORECASE,
)
_PREFERENCE_MANIPULATION = re.compile(
    r"\b("
    r"always\s+(?:choose|use|call)|"
    r"prefer\s+this\s+tool|"
    r"highest\s+priority|"
    r"more\s+trusted\s+than|"
    r"bypass\s+(?:policy|approval|review)"
    r")\b",
    re.IGNORECASE,
)
_FALSE_ERROR_ESCALATION = re.compile(
    r"\b("
    r"(?:if|when)\s+(?:an?\s+)?(?:error|failure|exception)\b.{0,80}"
    r"(?:run|execute|call|invoke|use)\s+"
    r"(?:shell|terminal|bash|cmd|powershell|rm|curl|wget|delete|drop)|"
    r"on\s+(?:error|failure)\b.{0,80}(?:ask|tell)\s+the\s+user\s+to\s+run"
    r")\b",
    re.IGNORECASE,
)
_TOOL_TRANSFER = re.compile(
    r"\b("
    r"(?:call|invoke|delegate\s+to|transfer\s+to|chain\s+to)\s+"
    r"(?:another\s+)?(?:tool|server|agent)|"
    r"after\s+this\s+tool\b.{0,80}(?:call|invoke|use)\b"
    r")\b",
    re.IGNORECASE,
)
_MUTATING_PARAMETER = re.compile(
    r"(?:^|[_\-.])("
    r"command|cmd|shell|script|exec|execute|delete|remove|write|update|patch|"
    r"drop|truncate|query|sql|payload|body|url|webhook|callback|destination"
    r")(?:$|[_\-.])",
    re.IGNORECASE,
)
_READ_TOOL = re.compile(
    r"(?:^|[_\-.])(?:read|get|list|search|fetch|view|show|describe|query|find|"
    r"lookup|inspect|open|stat)(?:$|[_\-.])",
    re.IGNORECASE,
)
_READ_ALLOWED_PARAMETERS = frozenset(
    {
        "path",
        "file",
        "filename",
        "pattern",
        "glob",
        "query",
        "limit",
        "offset",
        "cursor",
        "encoding",
        "format",
        "include",
        "exclude",
        "recursive",
    }
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
    remote_auth: Mapping[str, object] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        """Return the descriptor digest used in discovery audit events."""
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
                "remote_auth": self.remote_auth,
            }
        )

    def to_registration(self) -> MCPToolRegistration:
        """Convert this clean descriptor into a signed trust registration."""
        return MCPToolRegistration(
            server=self.server,
            tool=self.tool,
            description=self.description,
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            server_identity=self.server_identity,
            tool_schema={
                "description": self.description,
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
                "transport": self.transport,
            },
            argument_schema=self.argument_schema,
            allowed_transports=(self.transport,),
        ).signed()


@dataclass(frozen=True)
class MCPRemoteAuthContext:
    """Remote MCP transport and audience-binding evidence."""

    presented_audience: str
    expected_audience: str
    server_identity: Mapping[str, object]
    transport_provenance: str
    authenticated: bool = True

    def as_metadata(self) -> Mapping[str, object]:
        """Return the mapping stored on descriptors and calls."""
        return {
            "presented_audience": self.presented_audience,
            "expected_audience": self.expected_audience,
            "server_identity": dict(self.server_identity),
            "transport_provenance": self.transport_provenance,
            "authenticated": self.authenticated,
        }


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
        """Build a discovery request from descriptor objects."""
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
        """Return signed registrations only when discovery was permitted."""
        if not self.permitted:
            return ()
        return tuple(
            descriptor.to_registration() for descriptor in self.request.descriptors
        )

    def to_audit_event(self) -> dict[str, object]:
        """Return a redacted discovery audit event."""
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
        """Return the response body as stable text for review and digesting."""
        if isinstance(self.output, str):
            return self.output
        return _canonical(self.output)

    def to_evaluation(self) -> EvaluationRequest:
        """Build the response-review input without tainting benign output."""
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
        """Build a response decision from a Governor decision."""
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
        """Return a redacted response-review audit event."""
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
            "remote_auth": call.remote_auth,
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


def _context_digest(value: Mapping[str, object]) -> str:
    return _digest(value)


def _route(*, permitted: bool, escalated: bool) -> MCPGatewayRoute:
    if escalated:
        return "human"
    if permitted:
        return "allow"
    return "block"


def _normalise_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _transport(metadata: Mapping[str, object], fallback: str = "") -> str:
    value = metadata.get("transport")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return fallback.strip().lower()


def _remote_auth_findings(
    *,
    transport: str,
    server_identity: Mapping[str, object],
    remote_auth: Mapping[str, object],
) -> tuple[str, ...]:
    if transport not in _REMOTE_TRANSPORTS:
        return ()

    findings: list[str] = []
    if not remote_auth:
        return ("remote_auth_missing",)

    presented = str(remote_auth.get("presented_audience", "")).strip()
    expected = str(remote_auth.get("expected_audience", "")).strip()
    if not presented or not expected or presented != expected:
        findings.append("remote_audience_mismatch")

    auth_identity = remote_auth.get("server_identity")
    if not isinstance(auth_identity, Mapping) or not auth_identity:
        findings.append("remote_identity_missing")
    elif dict(auth_identity) != dict(server_identity):
        findings.append("remote_identity_mismatch")

    provenance = str(remote_auth.get("transport_provenance", "")).strip().lower()
    if provenance not in _TRUSTED_TRANSPORT_PROVENANCE:
        findings.append("remote_transport_unverified")

    if remote_auth.get("authenticated") is not True:
        findings.append("remote_auth_not_authenticated")

    return tuple(dict.fromkeys(findings))


def _remote_auth_metadata(
    value: Mapping[str, object] | MCPRemoteAuthContext | None,
) -> Mapping[str, object]:
    if value is None:
        return {}
    if isinstance(value, MCPRemoteAuthContext):
        return value.as_metadata()
    return dict(value)


def _capability_context_metadata(
    value: Mapping[str, object] | CapabilityContext | None,
) -> Mapping[str, object]:
    if value is None:
        return {}
    if isinstance(value, CapabilityContext):
        return {
            "subject": value.subject,
            "tenant": value.tenant,
            "session": value.session,
            "source_origin": value.source_origin,
            "tool": value.tool,
            "resource": value.resource,
            "action": value.action,
            "blast_radius": value.blast_radius.name.lower(),
            "now": value.now,
        }
    return dict(value)


def _capability_audit_projection(
    value: Mapping[str, object],
    policy: CapabilityPolicy | None,
) -> Mapping[str, object]:
    if not value:
        return {}
    context = CapabilityContext.from_mapping(value)
    projection: dict[str, object] = {
        "context_digest": _context_digest(value),
        "summary": context.redacted_summary(),
    }
    if policy is not None:
        projection["decision"] = policy.evaluate(context).audit_projection()
    return {
        **projection,
    }


def _discovery_text(descriptor: MCPToolDescriptor) -> str:
    return "\n".join(
        (
            descriptor.description,
            _canonical(descriptor.input_schema),
            _canonical(descriptor.output_schema),
            _canonical(descriptor.argument_schema),
            _canonical(descriptor.hidden_metadata),
            _canonical(descriptor.remote_auth),
        )
    )


def _iter_schema_names(value: object) -> tuple[str, ...]:
    names: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                named_mapping = key in {"properties", "$defs", "definitions"}
                named_sequence = key in {"required", "dependentRequired"}
                if (named_mapping and isinstance(child, Mapping)) or (
                    named_sequence
                    and isinstance(child, Sequence)
                    and not isinstance(child, str)
                ):
                    names.extend(str(name) for name in child)
                visit(child)
        elif isinstance(node, Sequence) and not isinstance(node, str):
            for item in node:
                visit(item)

    visit(value)
    return tuple(dict.fromkeys(names))


def _iter_default_text(value: object) -> tuple[str, ...]:
    texts: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                if key in {"default", "const", "examples", "example", "enum"}:
                    texts.append(_canonical(child))
                visit(child)
        elif isinstance(node, Sequence) and not isinstance(node, str):
            for item in node:
                visit(item)

    visit(value)
    return tuple(texts)


def _parameter_names(descriptor: MCPToolDescriptor) -> tuple[str, ...]:
    names = [
        *_iter_schema_names(descriptor.input_schema),
        *_iter_schema_names(descriptor.argument_schema),
    ]
    return tuple(dict.fromkeys(name for name in names if name.strip()))


def _default_texts(descriptor: MCPToolDescriptor) -> tuple[str, ...]:
    return (
        *_iter_default_text(descriptor.input_schema),
        *_iter_default_text(descriptor.argument_schema),
    )


def _descriptor_poisoning_findings(descriptor: MCPToolDescriptor) -> tuple[str, ...]:
    findings: list[str] = []
    text = _discovery_text(descriptor)
    hidden_text = _canonical(descriptor.hidden_metadata)
    parameter_names = _parameter_names(descriptor)
    default_texts = _default_texts(descriptor)

    if _DISCOVERY_POISONING.search(text):
        findings.append("discovery_poisoning")
    if any(_PARAMETER_POISONING.search(name) for name in parameter_names):
        findings.append("parameter_name_poisoning")
    if any(_DISCOVERY_POISONING.search(default) for default in default_texts):
        findings.append("schema_default_poisoning")
    if descriptor.hidden_metadata and (
        _DISCOVERY_POISONING.search(hidden_text)
        or _PREFERENCE_MANIPULATION.search(hidden_text)
    ):
        findings.append("hidden_metadata_poisoning")
    if _PREFERENCE_MANIPULATION.search(text):
        findings.append("preference_manipulation")
    if _FALSE_ERROR_ESCALATION.search(text):
        findings.append("false_error_escalation")
    if _TOOL_TRANSFER.search(text):
        findings.append("tool_transfer")
    if _out_of_scope_parameters(descriptor, parameter_names):
        findings.append("out_of_scope_parameter")

    return tuple(dict.fromkeys(findings))


def _descriptor_remote_auth_findings(
    descriptor: MCPToolDescriptor,
) -> tuple[str, ...]:
    return _remote_auth_findings(
        transport=descriptor.transport.strip().lower(),
        server_identity=descriptor.server_identity,
        remote_auth=descriptor.remote_auth,
    )


def _out_of_scope_parameters(
    descriptor: MCPToolDescriptor,
    parameter_names: tuple[str, ...],
) -> bool:
    if not _READ_TOOL.search(descriptor.tool):
        return False
    for name in parameter_names:
        normalised = name.strip().lower().replace("-", "_").replace(".", "_")
        if normalised in _READ_ALLOWED_PARAMETERS:
            continue
        if _MUTATING_PARAMETER.search(normalised):
            return True
    return False


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

        findings.extend(_descriptor_poisoning_findings(descriptor))
        findings.extend(_descriptor_remote_auth_findings(descriptor))

    return tuple(dict.fromkeys(findings))


class _MCPRemoteAuthDetector:
    """Fail closed when remote MCP calls lack audience-bound provenance."""

    name = "mcp_remote_auth"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Return a signal for remote MCP auth/provenance mismatches."""
        call = request.metadata.get(MCP_CALL_KEY)
        if not isinstance(call, MCPToolCall):
            return None

        transport = _transport(
            call.tool_schema,
            fallback=_transport(call.server_identity),
        )
        findings = _remote_auth_findings(
            transport=transport,
            server_identity=call.server_identity,
            remote_auth=call.remote_auth,
        )
        if not findings:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=0.9,
            locus=Locus.ACTION,
            signal_type="mcp_remote_auth",
            severity=Severity.HIGH,
            rationale="remote MCP call failed audience or provenance binding: "
            + ", ".join(findings),
        )


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
    capability_context: Mapping[str, object] = field(default_factory=dict)

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
        remote_auth: Mapping[str, object] | MCPRemoteAuthContext | None = None,
        capability_context: Mapping[str, object] | CapabilityContext | None = None,
        provenance: str = "",
        query: str = "",
        context: str = "",
        tenant_id: str = "",
        dry_run: bool = True,
    ) -> MCPGatewayRequest:
        """Build a gateway tool-call request from primitive call parts."""
        call = MCPToolCall(
            server=server,
            tool=tool,
            arguments=dict(arguments or {}),
            arg_provenance=dict(arg_provenance or {}),
            default_provenance=default_provenance or provenance,
            server_identity=dict(server_identity or {}),
            tool_schema=dict(tool_schema or {}),
            argument_schema=dict(argument_schema or {}),
            remote_auth=_remote_auth_metadata(remote_auth),
        )
        return cls(
            call=call,
            provenance=provenance or default_provenance,
            query=query,
            context=context,
            tenant_id=tenant_id,
            dry_run=dry_run,
            capability_context=_capability_context_metadata(capability_context),
        )

    def to_evaluation(self) -> EvaluationRequest:
        """Build the Governor request with both MCP inspection paths preserved."""
        return EvaluationRequest(
            query=self.query,
            context=self.context,
            action=serialise_call(self.call),
            action_provenance=self.provenance,
            tenant_id=self.tenant_id,
            metadata={
                MCP_CALL_KEY: self.call,
                "dry_run": self.dry_run,
                CAPABILITY_CONTEXT_KEY: self.capability_context,
            },
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
    policy_projection: Mapping[str, object]

    @classmethod
    def from_governor(cls, call: MCPToolCall, decision: Decision) -> MCPGatewayDecision:
        """Build a gateway decision from a Governor decision."""
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
            policy_projection={},
        )

    @classmethod
    def from_request_and_governor(
        cls,
        request: MCPGatewayRequest,
        decision: Decision,
        capability_policy: CapabilityPolicy | None,
    ) -> MCPGatewayDecision:
        """Build a gateway decision and attach redacted policy context evidence."""
        base = cls.from_governor(request.call, decision)
        return cls(
            decision=base.decision,
            call=base.call,
            call_digest=base.call_digest,
            schema_digest=base.schema_digest,
            route=base.route,
            permitted=base.permitted,
            escalated=base.escalated,
            risk=base.risk,
            requires_human=base.requires_human,
            firing=base.firing,
            request_digest=base.request_digest,
            policy_projection=_capability_audit_projection(
                request.capability_context,
                capability_policy,
            ),
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
            "policy": {
                **self.policy_projection,
                "rationale": self.decision.record.rationale,
            },
        }


class MCPGateway:
    """Review MCP discovery, tool calls, and tool responses."""

    def __init__(
        self,
        governor: Governor,
        *,
        capability_policy: CapabilityPolicy | None = None,
        response_governor: Governor | None = None,
    ) -> None:
        self._governor = governor
        self._capability_policy = capability_policy
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
        require_signed_registrations: bool = False,
        fusion_policy: FusionPolicy | None = None,
        capability_policy: CapabilityPolicy | None = None,
        approval: ApprovalHook | None = None,
        audit_sink: AuditSink | None = None,
    ) -> MCPGateway:
        """Create a default MCP action gateway from known-good registrations."""
        registry = MCPTrustRegistry(
            registrations,
            allow_dynamic_discovery=allow_dynamic_discovery,
            require_signed_registrations=require_signed_registrations,
        )
        detectors: list[Detector] = [
            MCPCallInspector(registry=registry),
            _MCPRemoteAuthDetector(),
            DestructiveCommandDetector(),
            BlastRadiusDetector(),
            OriginTaintDetector(),
        ]
        if capability_policy is not None:
            detectors.append(CapabilityPolicyDetector(capability_policy))
        ensemble = ParallelEnsembleScorer(detectors, policy=fusion_policy)
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
            capability_policy=capability_policy,
            response_governor=response_governor,
        )

    @classmethod
    def from_policy_store(
        cls,
        registrations: Sequence[MCPToolRegistration],
        policy_store: str | Path,
        *,
        capability_grants: Sequence[CapabilityGrant] = (),
        allow_dynamic_discovery: bool = False,
        require_signed_registrations: bool = False,
        approval: ApprovalHook | None = None,
        audit_sink: AuditSink | None = None,
    ) -> MCPGateway:
        """Create an MCP gateway from a persisted Guardrail-as-Code ledger."""
        from .policy_binding import gateway_from_policy_store

        return gateway_from_policy_store(
            cls,
            registrations,
            policy_store,
            capability_grants=capability_grants,
            allow_dynamic_discovery=allow_dynamic_discovery,
            require_signed_registrations=require_signed_registrations,
            approval=approval,
            audit_sink=audit_sink,
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
        return MCPGatewayDecision.from_request_and_governor(
            request,
            decision,
            self._capability_policy,
        )
