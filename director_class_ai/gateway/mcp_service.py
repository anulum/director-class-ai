# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP gateway loopback service

"""Loopback JSON service for the MCP gateway contract.

The service layer deliberately stays small and dependency-free. It wraps
``MCPGateway`` with three local JSON endpoints:

``POST /v1/mcp/discovery``
    Review advertised descriptors before adding permitted signed registrations to
    the service registry.
``POST /v1/mcp/review``
    Review a proposed tool call against the current signed registry.
``POST /v1/mcp/response``
    Review a tool response before later agent steps consume it.

The service never executes MCP tools. It returns only the existing redacted audit
projections from the gateway decisions, so raw argument values and raw response
payloads are not reflected back to callers.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal

from ..action import MCPToolCall, MCPToolRegistration
from ..core.governor import ApprovalHook, AuditSink
from ..policy import CapabilityGrant, CapabilityPolicy
from .mcp import (
    MCPDiscoveryRequest,
    MCPGateway,
    MCPGatewayRequest,
    MCPResponseRequest,
    MCPToolDescriptor,
)

__all__ = [
    "MCP_AUTH_HEADER",
    "MCPGatewayHTTPServer",
    "MCPGatewayService",
    "MCPGatewayServiceConfig",
    "MCPGatewayServiceResponse",
]

_Method = Literal["GET", "POST"]
MCP_AUTH_HEADER = "x-director-class-operator-key"


@dataclass(frozen=True)
class MCPGatewayServiceConfig:
    """Configuration for a local MCP gateway service instance."""

    allow_dynamic_discovery: bool = False
    require_signed_registrations: bool = True
    max_body_bytes: int = 1_048_576
    operator_key: str = ""


@dataclass(frozen=True)
class MCPGatewayServiceResponse:
    """HTTP-ready response from the loopback service dispatcher."""

    status: int
    body: Mapping[str, object]
    headers: Mapping[str, str] = field(
        default_factory=lambda: {"content-type": "application/json; charset=utf-8"}
    )

    def to_json(self) -> bytes:
        """Serialise the response body as deterministic UTF-8 JSON."""
        return json.dumps(
            self.body,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class MCPGatewayService:
    """Stateful loopback dispatcher around ``MCPGateway``.

    The service owns a signed in-memory registry. Permitted discovery decisions
    append signed registrations, then rebuild the underlying ``MCPGateway`` so
    later review calls use the updated registry. Rejected discovery leaves the
    registry unchanged.
    """

    def __init__(
        self,
        registrations: Sequence[MCPToolRegistration] = (),
        *,
        config: MCPGatewayServiceConfig | None = None,
        capability_policy: CapabilityPolicy | None = None,
        policy_store: str | Path | None = None,
        capability_grants: Sequence[CapabilityGrant] = (),
        approval: ApprovalHook | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        if capability_policy is not None and policy_store is not None:
            raise ValueError("pass either capability_policy or policy_store, not both")
        self._config = config or MCPGatewayServiceConfig()
        self._registrations = tuple(registrations)
        self._capability_policy = capability_policy
        self._policy_store = Path(policy_store) if policy_store is not None else None
        self._capability_grants = tuple(capability_grants)
        self._approval = approval
        self._audit_sink = audit_sink
        self._gateway = self._build_gateway()

    @property
    def registration_count(self) -> int:
        """Return the number of registrations currently trusted by the service."""
        return len(self._registrations)

    def handle(
        self,
        method: _Method,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        operator_key: str = "",
    ) -> MCPGatewayServiceResponse:
        """Dispatch a parsed JSON request to the matching service endpoint."""
        if method == "GET" and path == "/healthz":
            return MCPGatewayServiceResponse(
                HTTPStatus.OK,
                {"status": "ok", "registration_count": self.registration_count},
            )
        if self._config.operator_key and not hmac.compare_digest(
            operator_key,
            self._config.operator_key,
        ):
            return _error(HTTPStatus.UNAUTHORIZED, "unauthorized")
        if method != "POST":
            return _error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
        if payload is None:
            return _error(HTTPStatus.BAD_REQUEST, "missing_json_body")

        if path == "/v1/mcp/discovery":
            return self._handle_discovery(payload)
        if path == "/v1/mcp/review":
            return self._handle_review(payload)
        if path == "/v1/mcp/response":
            return self._handle_response(payload)
        return _error(HTTPStatus.NOT_FOUND, "unknown_endpoint")

    def _build_gateway(self) -> MCPGateway:
        if self._policy_store is not None:
            return MCPGateway.from_policy_store(
                self._registrations,
                self._policy_store,
                capability_grants=self._capability_grants,
                allow_dynamic_discovery=self._config.allow_dynamic_discovery,
                require_signed_registrations=self._config.require_signed_registrations,
                approval=self._approval,
                audit_sink=self._audit_sink,
            )
        return MCPGateway.from_registry(
            self._registrations,
            allow_dynamic_discovery=self._config.allow_dynamic_discovery,
            require_signed_registrations=self._config.require_signed_registrations,
            capability_policy=self._capability_policy,
            approval=self._approval,
            audit_sink=self._audit_sink,
        )

    def _handle_discovery(
        self, payload: Mapping[str, object]
    ) -> MCPGatewayServiceResponse:
        request = MCPDiscoveryRequest.from_descriptors(
            _string(payload.get("server")),
            [_descriptor(item) for item in _sequence(payload.get("descriptors"))],
            provenance=_string(payload.get("provenance")),
            tenant_id=_string(payload.get("tenant_id")),
        )
        decision = self._gateway.review_discovery(request)
        registrations = decision.registrations()
        if registrations:
            self._registrations = (*self._registrations, *registrations)
            self._gateway = self._build_gateway()
        body = {
            **decision.to_audit_event(),
            "registration_count": self.registration_count,
        }
        return MCPGatewayServiceResponse(
            HTTPStatus.OK if decision.permitted else HTTPStatus.FORBIDDEN,
            body,
        )

    def _handle_review(self, payload: Mapping[str, object]) -> MCPGatewayServiceResponse:
        self._refresh_gateway_if_policy_bound()
        request = MCPGatewayRequest.from_parts(
            _string(payload.get("server")),
            _string(payload.get("tool")),
            _mapping(payload.get("arguments")),
            arg_provenance=_string_mapping(payload.get("arg_provenance")),
            default_provenance=_string(payload.get("default_provenance")),
            server_identity=_mapping(payload.get("server_identity")),
            tool_schema=_mapping(payload.get("tool_schema")),
            argument_schema=_mapping(payload.get("argument_schema")),
            remote_auth=_mapping(payload.get("remote_auth")),
            provenance=_string(payload.get("provenance")),
            query=_string(payload.get("query")),
            context=_string(payload.get("context")),
            tenant_id=_string(payload.get("tenant_id")),
            dry_run=_bool(payload.get("dry_run"), default=True),
            capability_context=_mapping(payload.get("capability_context")),
        )
        decision = self._gateway.review(request)
        return MCPGatewayServiceResponse(
            HTTPStatus.OK if decision.permitted else HTTPStatus.FORBIDDEN,
            decision.to_audit_event(),
        )

    def _handle_response(
        self, payload: Mapping[str, object]
    ) -> MCPGatewayServiceResponse:
        self._refresh_gateway_if_policy_bound()
        request = MCPResponseRequest(
            call=_call(_mapping(payload.get("call"))),
            output=payload.get("output", ""),
            content_type=_string(payload.get("content_type"), default="text/plain"),
            error=_bool(payload.get("error"), default=False),
            provenance=_string(payload.get("provenance"), default="tool_output"),
            tenant_id=_string(payload.get("tenant_id")),
            metadata=_mapping(payload.get("metadata")),
        )
        decision = self._gateway.review_response(request)
        return MCPGatewayServiceResponse(
            HTTPStatus.OK if decision.permitted else HTTPStatus.FORBIDDEN,
            decision.to_audit_event(),
        )

    def _refresh_gateway_if_policy_bound(self) -> None:
        if self._policy_store is not None:
            self._gateway = self._build_gateway()


class MCPGatewayHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server with an attached ``MCPGatewayService``."""

    def __init__(
        self,
        server_address: tuple[str, int],
        service: MCPGatewayService,
    ) -> None:
        super().__init__(server_address, _Handler)
        self.service = service


class _Handler(BaseHTTPRequestHandler):
    server: MCPGatewayHTTPServer

    def log_message(self, format: str, *args: object) -> None:
        """Suppress BaseHTTPRequestHandler stderr logging in embedded use."""
        return None

    def do_GET(self) -> None:
        """Handle loopback service health checks."""
        self._send(
            self.server.service.handle(
                "GET",
                self.path,
                operator_key=self.headers.get(MCP_AUTH_HEADER, ""),
            )
        )

    def do_POST(self) -> None:
        """Handle JSON POST requests for the MCP gateway service."""
        length = _content_length(self.headers.get("content-length"))
        if length is None or length > self.server.service._config.max_body_bytes:
            self._send(_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large"))
            return
        raw = self.rfile.read(length)
        try:
            loaded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(_error(HTTPStatus.BAD_REQUEST, "invalid_json"))
            return
        if not isinstance(loaded, Mapping):
            self._send(_error(HTTPStatus.BAD_REQUEST, "json_body_must_be_object"))
            return
        self._send(
            self.server.service.handle(
                "POST",
                self.path,
                loaded,
                operator_key=self.headers.get(MCP_AUTH_HEADER, ""),
            )
        )

    def _send(self, response: MCPGatewayServiceResponse) -> None:
        body = response.to_json()
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _descriptor(value: object) -> MCPToolDescriptor:
    data = _mapping(value)
    return MCPToolDescriptor(
        server=_string(data.get("server")),
        tool=_string(data.get("tool")),
        description=_string(data.get("description")),
        instructions=_string(data.get("instructions")),
        input_schema=_mapping(data.get("input_schema")),
        output_schema=_mapping(data.get("output_schema")),
        argument_schema=_mapping(data.get("argument_schema")),
        server_identity=_mapping(data.get("server_identity")),
        transport=_string(data.get("transport"), default="stdio"),
        hidden_metadata=_mapping(data.get("hidden_metadata")),
        remote_auth=_mapping(data.get("remote_auth")),
    )


def _call(value: Mapping[str, object]) -> MCPToolCall:
    return MCPToolCall(
        server=_string(value.get("server")),
        tool=_string(value.get("tool")),
        arguments=_mapping(value.get("arguments")),
        arg_provenance=_string_mapping(value.get("arg_provenance")),
        default_provenance=_string(value.get("default_provenance")),
        server_identity=_mapping(value.get("server_identity")),
        tool_schema=_mapping(value.get("tool_schema")),
        argument_schema=_mapping(value.get("argument_schema")),
        remote_auth=_mapping(value.get("remote_auth")),
    )


def _content_length(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _string_mapping(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _sequence(value: object) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        return value
    return ()


def _string(value: object, *, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _bool(value: object, *, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _error(status: HTTPStatus, code: str) -> MCPGatewayServiceResponse:
    return MCPGatewayServiceResponse(status, {"error": code})
