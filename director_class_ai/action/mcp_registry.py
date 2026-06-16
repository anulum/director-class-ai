# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP trust registry

"""Trust registry for known MCP servers, tools, and argument schemas."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..core import DetectorSignal, EvaluationRequest, Locus, Plane, Severity
from .mcp_inspector import MCP_CALL_KEY, MCPToolCall

__all__ = ["MCPToolRegistration", "MCPTrustRegistry"]


def _canonical(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint(*parts: Mapping[str, object]) -> str:
    payload = "\x1f".join(_canonical(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _normalise_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


@dataclass(frozen=True)
class MCPToolRegistration:
    """Known-good identity and schema fingerprint for one MCP tool."""

    server: str
    tool: str
    server_identity: Mapping[str, object] = field(default_factory=dict)
    tool_schema: Mapping[str, object] = field(default_factory=dict)
    argument_schema: Mapping[str, object] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return _fingerprint(
            self.server_identity,
            self.tool_schema,
            self.argument_schema,
        )

    @property
    def key(self) -> tuple[str, str]:
        return (self.server, self.tool)

    def fingerprint_for(self, call: MCPToolCall) -> str:
        return _fingerprint(call.server_identity, call.tool_schema, call.argument_schema)


class MCPTrustRegistry:
    """Default-deny registry for MCP dynamic discovery and schema drift."""

    name = "mcp_trust_registry"
    plane = Plane.ACTION
    tier = 0

    def __init__(
        self,
        registrations: Sequence[MCPToolRegistration],
        *,
        allow_dynamic_discovery: bool = False,
    ) -> None:
        self._registrations = {
            registration.key: registration for registration in registrations
        }
        self._by_server: dict[str, list[MCPToolRegistration]] = {}
        for registration in registrations:
            self._by_server.setdefault(registration.server, []).append(registration)
        self._allow_dynamic_discovery = allow_dynamic_discovery

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        call = request.metadata.get(MCP_CALL_KEY)
        if not isinstance(call, MCPToolCall):
            return None

        registration = self._registrations.get((call.server, call.tool))
        if registration is None:
            lookalike = self._lookalike(call)
            if lookalike is not None:
                return _signal(
                    "mcp_lookalike_tool",
                    Severity.HIGH,
                    f"MCP tool {call.server}/{call.tool} resembles registered "
                    f"{lookalike.server}/{lookalike.tool}",
                )
            if self._allow_dynamic_discovery:
                return None
            return _signal(
                "mcp_unknown_tool",
                Severity.HIGH,
                f"MCP tool {call.server}/{call.tool} is not in the trust registry",
            )

        if registration.fingerprint_for(call) != registration.fingerprint:
            return _signal(
                "mcp_schema_drift",
                Severity.HIGH,
                f"MCP tool {call.server}/{call.tool} identity or schema "
                "fingerprint drift",
            )
        return None

    def _lookalike(self, call: MCPToolCall) -> MCPToolRegistration | None:
        tool_norm = _normalise_name(call.tool)
        for registration in self._by_server.get(call.server, []):
            if _normalise_name(registration.tool) == tool_norm:
                return registration
        return None


def _signal(signal_type: str, severity: Severity, rationale: str) -> DetectorSignal:
    return DetectorSignal(
        detector="mcp_trust_registry",
        plane=Plane.ACTION,
        score=0.9,
        locus=Locus.ACTION,
        signal_type=signal_type,
        severity=severity,
        rationale=rationale,
    )
