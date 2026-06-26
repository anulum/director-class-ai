# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP trust registry

"""Trust registry for known MCP servers, tools, and argument schemas."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace

from ..core import DetectorSignal, EvaluationRequest, Locus, Plane, Severity
from .mcp_inspector import MCP_CALL_KEY, MCPToolCall

__all__ = ["MCPToolRegistration", "MCPTrustRegistry"]


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint(*parts: object) -> str:
    payload = "\x1f".join(_canonical(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _normalise_name(value: str) -> str:
    folded = unicodedata.normalize("NFKC", value).casefold()
    skeleton = "".join(_CONFUSABLES.get(character, character) for character in folded)
    return re.sub(r"[^a-z0-9]+", "", skeleton)


_CONFUSABLES = {
    "а": "a",
    "ɑ": "a",
    "Α": "a",
    "α": "a",
    "В": "b",
    "в": "b",
    "ϲ": "c",
    "с": "c",
    "С": "c",
    "ԁ": "d",
    "е": "e",
    "Е": "e",
    "Ε": "e",
    "ε": "e",
    "і": "i",
    "І": "i",
    "ӏ": "l",
    "ⅼ": "l",
    "Ι": "i",
    "ı": "i",
    "ο": "o",
    "О": "o",
    "о": "o",
    "Ο": "o",
    "р": "p",
    "Р": "p",
    "ѕ": "s",
    "Տ": "s",
    "Τ": "t",
    "τ": "t",
    "υ": "u",
    "Ү": "y",
    "у": "y",
    "Υ": "y",
    "Χ": "x",
    "х": "x",
    "Ζ": "z",
}


def _edit_distance_at_most_one(left: str, right: str) -> bool:
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        differences = [
            index
            for index, pair in enumerate(zip(left, right, strict=True))
            if pair[0] != pair[1]
        ]
        if len(differences) == 1:
            return True
        if len(differences) == 2:
            first, second = differences
            return (
                second == first + 1
                and left[first] == right[second]
                and left[second] == right[first]
            )
        return False
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    index = 0
    while index < len(shorter) and shorter[index] == longer[index]:
        index += 1
    return shorter[index:] == longer[index + 1 :]


def _normalise_transports(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({value.strip().lower() for value in values if value.strip()}))


def _mapping_value(mapping: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = mapping.get(key)
    return value if isinstance(value, Mapping) else {}


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _property_schema(
    schema: Mapping[str, object],
    name: str,
) -> Mapping[str, object]:
    properties = _mapping_value(schema, "properties")
    value = properties.get(name)
    return value if isinstance(value, Mapping) else {}


def _schema_types(schema: Mapping[str, object]) -> tuple[str, ...]:
    value = schema.get("type")
    if isinstance(value, str):
        return (value,)
    return _string_sequence(value)


def _matches_schema_type(value: object, schema_type: str) -> bool:
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return (isinstance(value, int | float)) and not isinstance(value, bool)
    if schema_type == "boolean":
        return isinstance(value, bool)
    if schema_type == "object":
        return isinstance(value, Mapping)
    if schema_type == "array":
        return isinstance(value, Sequence) and not isinstance(value, str)
    if schema_type == "null":
        return value is None
    return False


def _argument_schema_violation(
    arguments: Mapping[str, object],
    schema: Mapping[str, object],
) -> str:
    required = _string_sequence(schema.get("required"))
    for name in required:
        if name not in arguments:
            return f"missing required argument {name!r}"

    properties = _mapping_value(schema, "properties")
    if schema.get("additionalProperties") is False:
        for name in sorted(arguments):
            if name not in properties:
                return f"unexpected argument {name!r}"

    for name, value in arguments.items():
        property_schema = _property_schema(schema, name)
        if not property_schema:
            continue
        allowed = _schema_types(property_schema)
        if allowed and not any(_matches_schema_type(value, kind) for kind in allowed):
            return f"argument {name!r} must be {' or '.join(allowed)}"
        enum = property_schema.get("enum")
        if isinstance(enum, Sequence) and not isinstance(enum, str) and value not in enum:
            return f"argument {name!r} must match one of the registered enum values"
    return ""


@dataclass(frozen=True)
class MCPToolRegistration:
    """Known-good identity and schema fingerprint for one MCP tool."""

    server: str
    tool: str
    description: str = ""
    input_schema: Mapping[str, object] = field(default_factory=dict)
    output_schema: Mapping[str, object] = field(default_factory=dict)
    server_identity: Mapping[str, object] = field(default_factory=dict)
    tool_schema: Mapping[str, object] = field(default_factory=dict)
    argument_schema: Mapping[str, object] = field(default_factory=dict)
    allowed_transports: tuple[str, ...] = ("stdio",)
    registry_signature: str = ""

    def __post_init__(self) -> None:
        """Normalise allowed transports after dataclass initialisation."""
        object.__setattr__(
            self,
            "allowed_transports",
            _normalise_transports(self.allowed_transports),
        )

    @property
    def manifest(self) -> Mapping[str, object]:
        """Return the signed registry manifest for this tool registration."""
        return {
            "server": self.server,
            "tool": self.tool,
            "description": self.description
            or str(self.tool_schema.get("description", "")),
            "input_schema": self.input_schema
            or _mapping_value(self.tool_schema, "input_schema"),
            "output_schema": self.output_schema
            or _mapping_value(self.tool_schema, "output_schema"),
            "server_identity": self.server_identity,
            "tool_schema": self.tool_schema,
            "argument_schema": self.argument_schema,
            "allowed_transports": self.allowed_transports,
        }

    @property
    def fingerprint(self) -> str:
        """Return the stable digest for the registry manifest."""
        return _fingerprint(self.manifest)

    @property
    def signature_valid(self) -> bool:
        """Return whether the stored signature matches the current manifest."""
        if not self.registry_signature:
            return True
        return hmac.compare_digest(self.registry_signature, self.fingerprint)

    @property
    def population_issues(self) -> tuple[str, ...]:
        """Return manifest fields that are too empty to enforce trust."""
        issues: list[str] = []
        if not self.server.strip():
            issues.append("server")
        if not self.tool.strip():
            issues.append("tool")
        if not self.server_identity:
            issues.append("server_identity")
        if not self.tool_schema:
            issues.append("tool_schema")
        if not self.argument_schema:
            issues.append("argument_schema")
        return tuple(issues)

    @property
    def key(self) -> tuple[str, str]:
        """Return the lookup key used by the trust registry."""
        return (self.server, self.tool)

    def signed(self) -> MCPToolRegistration:
        """Return a copy whose signature is bound to the current manifest."""
        return replace(self, registry_signature=self.fingerprint)

    def fingerprint_for(self, call: MCPToolCall) -> str:
        """Return the manifest digest that a runtime call must match."""
        return _fingerprint(
            {
                "server": call.server,
                "tool": call.tool,
                "description": self.description
                or str(call.tool_schema.get("description", "")),
                "input_schema": self.input_schema
                or _mapping_value(call.tool_schema, "input_schema"),
                "output_schema": self.output_schema
                or _mapping_value(call.tool_schema, "output_schema"),
                "server_identity": call.server_identity,
                "tool_schema": call.tool_schema,
                "argument_schema": call.argument_schema,
                "allowed_transports": self.allowed_transports,
            }
        )

    def call_transport(self, call: MCPToolCall) -> str:
        """Extract the declared transport from a runtime call, if present."""
        for metadata in (call.tool_schema, call.server_identity):
            value = metadata.get("transport")
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
        return ""


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
        require_signed_registrations: bool = False,
    ) -> None:
        self._registrations = {
            registration.key: registration for registration in registrations
        }
        self._by_server: dict[str, list[MCPToolRegistration]] = {}
        for registration in registrations:
            self._by_server.setdefault(registration.server, []).append(registration)
        self._allow_dynamic_discovery = allow_dynamic_discovery
        self._require_signed_registrations = require_signed_registrations

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Fail closed on unknown tools, manifest drift, and policy violations."""
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

        population_issues = registration.population_issues
        if population_issues:
            return _signal(
                "mcp_underpopulated_registration",
                Severity.HIGH,
                f"MCP tool {call.server}/{call.tool} registration missing "
                f"required manifest fields: {', '.join(population_issues)}",
            )
        if self._require_signed_registrations and not registration.registry_signature:
            return _signal(
                "mcp_unsigned_registration",
                Severity.HIGH,
                f"MCP tool {call.server}/{call.tool} registration is not signed",
            )
        if not registration.signature_valid:
            return _signal(
                "mcp_registration_signature_mismatch",
                Severity.HIGH,
                f"MCP tool {call.server}/{call.tool} registry signature mismatch",
            )
        if registration.allowed_transports:
            transport = registration.call_transport(call)
            if transport and transport not in registration.allowed_transports:
                return _signal(
                    "mcp_transport_mismatch",
                    Severity.HIGH,
                    f"MCP tool {call.server}/{call.tool} transport is not allowed",
                )

        if registration.fingerprint_for(call) != registration.fingerprint:
            return _signal(
                "mcp_schema_drift",
                Severity.HIGH,
                f"MCP tool {call.server}/{call.tool} identity or schema "
                "fingerprint drift",
            )
        schema_violation = _argument_schema_violation(
            call.arguments,
            registration.argument_schema,
        )
        if schema_violation:
            return _signal(
                "mcp_argument_schema_violation",
                Severity.HIGH,
                f"MCP tool {call.server}/{call.tool} argument schema violation: "
                f"{schema_violation}",
            )
        return None

    def _lookalike(self, call: MCPToolCall) -> MCPToolRegistration | None:
        tool_norm = _normalise_name(call.tool)
        for registration in self._registrations.values():
            registered_norm = _normalise_name(registration.tool)
            if registered_norm == tool_norm:
                return registration
            if _edit_distance_at_most_one(registered_norm, tool_norm):
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
