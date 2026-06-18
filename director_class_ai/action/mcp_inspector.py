# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP tool-call inspector (action plane, tier 0)

"""Inspect a *structured* MCP tool call, not just its flattened string form.

The shell / SQL string detectors run on a serialised command and catch destructive
payloads. They cannot see what makes an MCP tool call dangerous in ways a string
loses: a single argument value lifted from a retrieved document while the rest of
the call came from the user (argument-granular taint — the lethal-trifecta
injection path), a read-named tool being steered to touch ``/etc`` or ``~/.ssh``
(the confused-deputy / exfiltration pattern), or a secret-bearing argument paired
with an off-host destination (data exfiltration). This inspector reasons over the
:class:`MCPToolCall` structure carried in ``EvaluationRequest.metadata`` and emits
the strongest structural signal it finds; the serialised action string is left to
the destructive-command and blast-radius detectors, so the two are complementary.

``OriginTaintDetector`` keys off a *single* call-level provenance; this inspector
keys off ``arg_provenance`` per argument, so a call whose overall provenance looks
like ``"user"`` but whose ``path`` argument was sourced from ``"retrieved"`` content
is still caught here.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TypeAlias

from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)
from ._lexicon import IRREVERSIBLE, MUTATING, SYSTEM_TARGET, UNTRUSTED_ORIGINS

__all__ = [
    "MCPToolCall",
    "MCPCallInspector",
    "mcp_rust_scanner_available",
    "serialise_call",
    "MCP_CALL_KEY",
]

#: metadata key under which an :class:`MCPToolCall` is carried to the detectors.
MCP_CALL_KEY = "mcp_call"

# Argument keys whose *purpose* is to name an outbound destination.
_DESTINATION_KEYS = frozenset(
    {
        "url",
        "uri",
        "endpoint",
        "webhook",
        "callback",
        "host",
        "hostname",
        "target",
        "dest",
        "destination",
        "to",
        "recipient",
        "address",
        "server",
    }
)

# Argument keys whose *purpose* is to carry a secret.
_SECRET_KEYS = frozenset(
    {
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "private_key",
        "credential",
        "credentials",
        "authorization",
        "auth",
        "session",
        "cookie",
    }
)

# A value that looks like an off-host destination.
_OFF_HOST_URL = re.compile(r"\bhttps?://|\bftp://|@[\w.-]+:", re.IGNORECASE)

# Values that look like a credential / key material (targeted, low false-positive).
_SECRET_VALUE = re.compile(
    r"AKIA[0-9A-Z]{12,}"  # AWS access key id
    r"|ghp_[A-Za-z0-9]{20,}"  # GitHub PAT
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"  # Slack token
    r"|sk-[A-Za-z0-9]{20,}"  # OpenAI-style secret key
    r"|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",  # PEM private key
)

# Path traversal escaping the intended root.
_TRAVERSAL = re.compile(r"(?:^|[\s,;:=\"'(\\/])\.\.(?:[\\/]|$)")

# Read-class tool verbs — a tool whose job is to read should not be driving writes.
_READ_VERBS = frozenset(
    {
        "get",
        "read",
        "list",
        "search",
        "fetch",
        "view",
        "show",
        "describe",
        "query",
        "find",
        "lookup",
        "count",
        "inspect",
        "grep",
        "open",
        "cat",
        "load",
        "download",
        "scan",
        "stat",
    }
)

_RustMCPScan: TypeAlias = Callable[
    [str, list[tuple[str, str, str, bool]]], tuple[float, str, str] | None
]


@dataclass(frozen=True)
class MCPToolCall:
    """A structured Model Context Protocol tool invocation an agent proposes.

    ``arg_provenance`` maps an argument name to where *that value* came from
    (``"user"``, ``"retrieved"``, ``"tool_output"``, …); an argument absent from the
    map inherits ``default_provenance``. This per-argument granularity is what lets
    the inspector catch a single tainted argument inside an otherwise-trusted call.
    """

    server: str
    tool: str
    arguments: Mapping[str, object] = field(default_factory=dict)
    arg_provenance: Mapping[str, str] = field(default_factory=dict)
    default_provenance: str = ""
    server_identity: Mapping[str, object] = field(default_factory=dict)
    tool_schema: Mapping[str, object] = field(default_factory=dict)
    argument_schema: Mapping[str, object] = field(default_factory=dict)
    remote_auth: Mapping[str, object] = field(default_factory=dict)

    def provenance_of(self, key: str) -> str:
        """Return the normalised provenance for one argument key."""
        return (self.arg_provenance.get(key) or self.default_provenance).strip().lower()

    def is_tainted(self, key: str) -> bool:
        """Return true when an argument value came from an untrusted origin."""
        return self.provenance_of(key) in UNTRUSTED_ORIGINS


def serialise_call(call: MCPToolCall) -> str:
    """Render a tool call as an action string the string detectors can analyse.

    Each argument value is placed on its own line so a value ending in a path
    separator is followed by whitespace — preserving the boundaries the
    destructive-command rules anchor on.
    """
    lines = [f"{call.server}/{call.tool}"]
    lines += [f"{key}={value}" for key, value in call.arguments.items()]
    return "\n".join(lines)


def _tool_is_mutating(tool: str) -> bool:
    return bool(MUTATING.search(tool.replace("_", " ").replace("-", " ")))


def _tool_is_read(tool: str) -> bool:
    tokens = re.split(r"[^A-Za-z]+", tool.lower())
    return any(token in _READ_VERBS for token in tokens if token)


@dataclass(frozen=True)
class _Finding:
    score: float
    severity: Severity
    reason: str


def _load_rust_mcp_scan() -> _RustMCPScan | None:
    try:
        module = importlib.import_module("director_class_ai._rust")
    except ImportError:
        return None
    scan = getattr(module, "mcp_structural_scan", None)
    return scan if callable(scan) else None


_RUST_MCP_SCAN = _load_rust_mcp_scan()


def mcp_rust_scanner_available() -> bool:
    """Return whether the optional Rust MCP structural scanner is importable."""
    return _RUST_MCP_SCAN is not None


def _taint_findings(call: MCPToolCall) -> list[_Finding]:
    findings: list[_Finding] = []
    for key, value in call.arguments.items():
        if not call.is_tainted(key):
            continue
        origin = call.provenance_of(key)
        if _tool_is_mutating(call.tool) or MUTATING.search(str(value)):
            findings.append(
                _Finding(
                    0.85,
                    Severity.HIGH,
                    f"argument {key!r} sourced from {origin!r} content drives a "
                    f"state-changing tool call (injection→effector path)",
                )
            )
        else:
            findings.append(
                _Finding(
                    0.6,
                    Severity.MEDIUM,
                    f"argument {key!r} sourced from {origin!r} content",
                )
            )
    return findings


def _confused_deputy_findings(call: MCPToolCall) -> list[_Finding]:
    if not _tool_is_read(call.tool) or _tool_is_mutating(call.tool):
        return []
    findings: list[_Finding] = []
    for key, value in call.arguments.items():
        text = str(value)
        if SYSTEM_TARGET.search(text):
            findings.append(
                _Finding(
                    0.7,
                    Severity.HIGH,
                    f"read-class tool {call.tool!r} pointed at a system / secret "
                    f"path via {key!r}",
                )
            )
        elif IRREVERSIBLE.search(text) or MUTATING.search(text):
            findings.append(
                _Finding(
                    0.6,
                    Severity.MEDIUM,
                    f"read-class tool {call.tool!r} carries a state-changing "
                    f"argument {key!r}",
                )
            )
    return findings


def _is_destination(key: str, value: str) -> bool:
    return key.lower() in _DESTINATION_KEYS or bool(_OFF_HOST_URL.search(value))


def _is_secret(key: str, value: str) -> bool:
    return key.lower() in _SECRET_KEYS or bool(_SECRET_VALUE.search(value))


def _exfiltration_findings(call: MCPToolCall) -> list[_Finding]:
    has_destination = False
    has_secret = False
    for key, value in call.arguments.items():
        text = str(value)
        has_destination = has_destination or _is_destination(key, text)
        has_secret = has_secret or _is_secret(key, text)
    if has_destination and has_secret:
        return [
            _Finding(
                0.85,
                Severity.HIGH,
                "secret-bearing argument paired with an external destination "
                "(data-exfiltration shape)",
            )
        ]
    return []


def _traversal_findings(call: MCPToolCall) -> list[_Finding]:
    findings: list[_Finding] = []
    for key, value in call.arguments.items():
        if _TRAVERSAL.search(str(value)):
            findings.append(
                _Finding(0.6, Severity.MEDIUM, f"path traversal in argument {key!r}")
            )
    return findings


def _scan_python(call: MCPToolCall) -> tuple[float, Severity, str] | None:
    findings = (
        _taint_findings(call)
        + _confused_deputy_findings(call)
        + _exfiltration_findings(call)
        + _traversal_findings(call)
    )
    if not findings:
        return None
    findings.sort(key=lambda f: (f.severity, f.score), reverse=True)
    top = findings[0]
    reasons = list(dict.fromkeys(f.reason for f in findings))[:3]
    return top.score, top.severity, "; ".join(reasons)


def _severity_from_rust(name: str) -> Severity | None:
    try:
        return Severity[name.upper()]
    except KeyError:
        return None


def _rust_scan_to_python(
    result: tuple[float, str, str] | None,
) -> tuple[float, Severity, str] | None:
    if result is None:
        return None
    score, severity_name, rationale = result
    severity = _severity_from_rust(severity_name)
    if severity is None:
        return None
    return score, severity, rationale


def _rust_inputs(call: MCPToolCall) -> list[tuple[str, str, str, bool]]:
    return [
        (key, str(value), call.provenance_of(key), call.is_tainted(key))
        for key, value in call.arguments.items()
    ]


def _scan_structural(call: MCPToolCall) -> tuple[float, Severity, str] | None:
    python_result = _scan_python(call)
    if _RUST_MCP_SCAN is None:
        return python_result
    try:
        rust_result = _rust_scan_to_python(_RUST_MCP_SCAN(call.tool, _rust_inputs(call)))
    except Exception:
        return python_result
    return rust_result if rust_result == python_result else python_result


class MCPCallInspector:
    """Tier-0 action-plane detector for the structure of an MCP tool call."""

    name = "mcp_call_inspector"
    plane = Plane.ACTION
    tier = 0

    def __init__(self, registry: object | None = None) -> None:
        self._registry = registry

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Inspect structured MCP metadata before serialised-action detectors run."""
        call = request.metadata.get(MCP_CALL_KEY)
        if not isinstance(call, MCPToolCall):
            return None
        if self._registry is not None and hasattr(self._registry, "evaluate"):
            registry_signal = self._registry.evaluate(request)
            if isinstance(registry_signal, DetectorSignal):
                return registry_signal
        structural = _scan_structural(call)
        if structural is None:
            return None
        score, severity, rationale = structural
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=score,
            locus=Locus.ACTION,
            signal_type="mcp_tool_call",
            severity=severity,
            rationale=rationale,
        )
