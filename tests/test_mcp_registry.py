# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP trust registry tests

from __future__ import annotations

from director_class_ai.action.mcp_inspector import MCP_CALL_KEY, MCPToolCall
from director_class_ai.action.mcp_registry import MCPToolRegistration, MCPTrustRegistry
from director_class_ai.core import EvaluationRequest, Severity


def _registration() -> MCPToolRegistration:
    return MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read a project file", "mode": "read"},
        argument_schema={
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    )


def _call(**overrides: object) -> MCPToolCall:
    values = {
        "server": "fs",
        "tool": "read_file",
        "arguments": {"path": "README.md"},
        "server_identity": {"transport": "stdio", "name": "local-fs"},
        "tool_schema": {"mode": "read", "description": "read a project file"},
        "argument_schema": {
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
        },
    }
    values.update(overrides)
    return MCPToolCall(**values)


def test_registration_fingerprint_is_stable_across_mapping_order() -> None:
    first = _registration()
    second = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"transport": "stdio", "name": "local-fs"},
        tool_schema={"mode": "read", "description": "read a project file"},
        argument_schema={
            "required": ["path"],
            "properties": {"path": {"type": "string"}},
        },
    )
    assert first.fingerprint == second.fingerprint


def test_registered_tool_with_matching_schema_is_accepted() -> None:
    registry = MCPTrustRegistry([_registration()])
    assert registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: _call()})) is None


def test_non_mcp_metadata_is_ignored() -> None:
    registry = MCPTrustRegistry([_registration()])
    assert (
        registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: "not-a-call"}))
        is None
    )


def test_unknown_tool_is_denied_by_default() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(metadata={MCP_CALL_KEY: _call(tool="delete_file")})
    )
    assert sig is not None
    assert sig.signal_type == "mcp_unknown_tool"
    assert sig.severity is Severity.HIGH


def test_dynamic_discovery_policy_allows_unknown_tool() -> None:
    registry = MCPTrustRegistry([_registration()], allow_dynamic_discovery=True)
    assert (
        registry.evaluate(
            EvaluationRequest(metadata={MCP_CALL_KEY: _call(tool="delete_file")})
        )
        is None
    )


def test_lookalike_tool_is_detected() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(metadata={MCP_CALL_KEY: _call(tool="read-file")})
    )
    assert sig is not None
    assert sig.signal_type == "mcp_lookalike_tool"
    assert "read_file" in sig.rationale


def test_schema_drift_is_detected() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={
                MCP_CALL_KEY: _call(
                    argument_schema={
                        "properties": {"path": {"type": "string"}},
                        "required": ["path", "encoding"],
                    }
                )
            }
        )
    )
    assert sig is not None
    assert sig.signal_type == "mcp_schema_drift"
    assert sig.severity is Severity.HIGH
