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
from ..detectors import default_content_integrity_detectors
from ..policy import (
    CAPABILITY_CONTEXT_KEY,
    CapabilityContext,
    CapabilityPolicy,
)
from ..policy.capability import CapabilityPolicyDetector
from .mcp_discovery_rules import (
    descriptor_poisoning_findings,
    normalise_tool_name,
)

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


@dataclass(frozen=True)
class MCPToolDescriptor:
    """One MCP tool descriptor received during discovery."""

    server: str
    tool: str
    description: str = ""
    instructions: str = ""
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
                "instructions": self.instructions,
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
        tool_schema = {
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "transport": self.transport,
        }
        if self.instructions:
            tool_schema["instructions"] = self.instructions
        return MCPToolRegistration(
            server=self.server,
            tool=self.tool,
            description=self.description,
            input_schema=self.input_schema,
            output_schema=self.output_schema,
            server_identity=self.server_identity,
            tool_schema=tool_schema,
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


def _descriptor_evaluation_request(
    request: MCPDiscoveryRequest,
    descriptor: MCPToolDescriptor,
) -> EvaluationRequest:
    """Build a detector request for semantic review of one discovery descriptor."""
    text = "\n".join(
        (
            descriptor.description,
            descriptor.instructions,
            _canonical(descriptor.input_schema),
            _canonical(descriptor.output_schema),
            _canonical(descriptor.argument_schema),
            _canonical(descriptor.hidden_metadata),
        )
    )
    return EvaluationRequest(
        query=descriptor.tool,
        response=text,
        context=text,
        action=descriptor.tool,
        action_provenance=request.provenance,
        tenant_id=request.tenant_id,
    )


def _route(*, permitted: bool, escalated: bool) -> MCPGatewayRoute:
    if escalated:
        return "human"
    if permitted:
        return "allow"
    return "block"


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


def _descriptor_remote_auth_findings(
    descriptor: MCPToolDescriptor,
) -> tuple[str, ...]:
    return _remote_auth_findings(
        transport=descriptor.transport.strip().lower(),
        server_identity=descriptor.server_identity,
        remote_auth=descriptor.remote_auth,
    )


def _review_discovery(
    request: MCPDiscoveryRequest,
    pinned_registrations: Sequence[MCPToolRegistration] = (),
) -> tuple[str, ...]:
    findings: list[str] = []
    if not request.server.strip():
        findings.append("missing_server")
    if not request.descriptors:
        findings.append("empty_discovery")

    pinned = {
        registration.key: registration
        for registration in pinned_registrations
        if registration.server == request.server
    }
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
        pinned_registration = pinned.get(exact)
        if (
            pinned_registration is not None
            and descriptor.to_registration().fingerprint
            != pinned_registration.fingerprint
        ):
            findings.append("tofu_pin_mismatch")

        normalised = (descriptor.server, normalise_tool_name(descriptor.tool))
        previous = seen_normalised.get(normalised)
        if previous is not None and previous != descriptor.tool:
            findings.append("tool_name_collision")
        seen_normalised[normalised] = descriptor.tool

        findings.extend(descriptor_poisoning_findings(descriptor))
        findings.extend(_descriptor_remote_auth_findings(descriptor))

    for key in pinned:
        if key not in seen_exact:
            findings.append("tofu_pin_missing")

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
        pinned_registrations: Sequence[MCPToolRegistration] = (),
        semantic_detectors: Sequence[Detector] | None = None,
    ) -> None:
        self._governor = governor
        self._capability_policy = capability_policy
        self._pinned_registrations = tuple(pinned_registrations)
        self._semantic_detectors = tuple(
            default_content_integrity_detectors()
            if semantic_detectors is None
            else semantic_detectors
        )
        self._response_governor = response_governor or Governor(
            ensemble=ParallelEnsembleScorer(
                [
                    DestructiveCommandDetector(),
                    BlastRadiusDetector(),
                    *self._semantic_detectors,
                ]
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
        semantic_detectors: Sequence[Detector] | None = None,
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
        semantic_detector_set = tuple(
            default_content_integrity_detectors()
            if semantic_detectors is None
            else semantic_detectors
        )
        response_detectors: list[Detector] = [
            DestructiveCommandDetector(),
            BlastRadiusDetector(),
            *semantic_detector_set,
        ]
        response_governor = Governor(
            ensemble=ParallelEnsembleScorer(response_detectors),
            approval=approval,
            audit_sink=audit_sink,
        )
        return cls(
            call_governor,
            capability_policy=capability_policy,
            response_governor=response_governor,
            pinned_registrations=registrations,
            semantic_detectors=semantic_detector_set,
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
        findings = (
            *_review_discovery(request, self._pinned_registrations),
            *self._semantic_discovery_findings(request),
        )
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

    def _semantic_discovery_findings(
        self, request: MCPDiscoveryRequest
    ) -> tuple[str, ...]:
        """Return fail-closed findings from optional semantic discovery detectors."""
        findings: list[str] = []
        for descriptor in request.descriptors:
            evaluation = _descriptor_evaluation_request(request, descriptor)
            for detector in self._semantic_detectors:
                signal = detector.evaluate(evaluation)
                if signal is not None:
                    findings.append(f"semantic_{signal.signal_type}")
        return tuple(dict.fromkeys(findings))

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
