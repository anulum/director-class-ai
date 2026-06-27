# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP trust registry tests

from __future__ import annotations

import director_class_ai.action.mcp_registry as mcp_registry
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


def test_registration_signature_binds_manifest() -> None:
    signed = _registration().signed()
    tampered = MCPToolRegistration(
        server=signed.server,
        tool=signed.tool,
        server_identity=signed.server_identity,
        tool_schema={"description": "read a different file", "mode": "read"},
        argument_schema=signed.argument_schema,
        registry_signature=signed.registry_signature,
    )

    assert signed.signature_valid is True
    assert tampered.signature_valid is False


def test_registered_tool_with_matching_schema_is_accepted() -> None:
    registry = MCPTrustRegistry([_registration()])
    assert registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: _call()})) is None


def test_signed_registration_is_accepted_when_signature_required() -> None:
    registry = MCPTrustRegistry(
        [_registration().signed()],
        require_signed_registrations=True,
    )
    assert registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: _call()})) is None


def test_unsigned_registration_is_denied_when_signature_required() -> None:
    registry = MCPTrustRegistry(
        [_registration()],
        require_signed_registrations=True,
    )
    sig = registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: _call()}))

    assert sig is not None
    assert sig.signal_type == "mcp_unsigned_registration"
    assert sig.severity is Severity.HIGH


def test_registration_signature_mismatch_is_denied() -> None:
    registration = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read a project file", "mode": "read"},
        argument_schema={
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        registry_signature="not-the-current-manifest-digest",
    )
    registry = MCPTrustRegistry([registration])
    sig = registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: _call()}))

    assert sig is not None
    assert sig.signal_type == "mcp_registration_signature_mismatch"


def test_underpopulated_registration_is_denied() -> None:
    registry = MCPTrustRegistry([MCPToolRegistration(server="fs", tool="read_file")])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={MCP_CALL_KEY: MCPToolCall("fs", "read_file", {"path": "README.md"})}
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_underpopulated_registration"
    assert "server_identity" in sig.rationale
    assert "tool_schema" in sig.rationale
    assert "argument_schema" in sig.rationale


def test_signed_underpopulated_registration_is_denied() -> None:
    registry = MCPTrustRegistry(
        [MCPToolRegistration(server="fs", tool="read_file").signed()],
        require_signed_registrations=True,
    )
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={MCP_CALL_KEY: MCPToolCall("fs", "read_file", {"path": "README.md"})}
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_underpopulated_registration"


def test_transport_mismatch_is_denied() -> None:
    registry = MCPTrustRegistry([_registration().signed()])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={
                MCP_CALL_KEY: _call(
                    server_identity={"name": "local-fs", "transport": "http"}
                )
            }
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_transport_mismatch"


def test_empty_transport_allow_list_skips_transport_gate() -> None:
    registration = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read a project file", "mode": "read"},
        argument_schema={
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        allowed_transports=(),
    ).signed()
    registry = MCPTrustRegistry([registration])

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


def test_cross_server_confusable_lookalike_tool_is_detected() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={MCP_CALL_KEY: _call(server="remote-fs", tool="read_f\u0456le")}
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_lookalike_tool"
    assert "fs/read_file" in sig.rationale


def test_cross_server_edit_distance_lookalike_tool_is_detected() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={MCP_CALL_KEY: _call(server="remote-fs", tool="read_fiel")}
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_lookalike_tool"


def test_exact_cross_server_tool_name_is_reported_as_lookalike() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={MCP_CALL_KEY: _call(server="remote-fs", tool="read_file")}
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_lookalike_tool"


def test_two_difference_tool_name_is_not_a_lookalike() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={MCP_CALL_KEY: _call(server="remote-fs", tool="write_blob")}
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_unknown_tool"


def test_dynamic_discovery_keeps_cross_server_lookalike_blocked() -> None:
    registry = MCPTrustRegistry([_registration()], allow_dynamic_discovery=True)
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={MCP_CALL_KEY: _call(server="remote-fs", tool="read_fiel")}
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_lookalike_tool"


def test_edit_distance_helper_covers_boundary_shapes() -> None:
    assert mcp_registry._edit_distance_at_most_one("read", "read") is True
    assert mcp_registry._edit_distance_at_most_one("read", "road") is True
    assert mcp_registry._edit_distance_at_most_one("read", "wxyz") is False
    assert mcp_registry._edit_distance_at_most_one("read", "reads") is True


def test_missing_required_argument_is_denied() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(metadata={MCP_CALL_KEY: _call(arguments={})})
    )

    assert sig is not None
    assert sig.signal_type == "mcp_argument_schema_violation"
    assert "missing required argument 'path'" in sig.rationale


def test_wrong_argument_type_is_denied() -> None:
    registry = MCPTrustRegistry([_registration()])
    sig = registry.evaluate(
        EvaluationRequest(metadata={MCP_CALL_KEY: _call(arguments={"path": 7})})
    )

    assert sig is not None
    assert sig.signal_type == "mcp_argument_schema_violation"
    assert "argument 'path' must be string" in sig.rationale


def test_unexpected_argument_is_denied_when_schema_is_closed() -> None:
    registration = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read a project file", "mode": "read"},
        argument_schema={
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    )
    registry = MCPTrustRegistry([registration])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={
                MCP_CALL_KEY: _call(
                    arguments={"path": "README.md", "payload": "rm -rf /"},
                    argument_schema=registration.argument_schema,
                )
            }
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_argument_schema_violation"
    assert "unexpected argument 'payload'" in sig.rationale


def test_nested_object_argument_schema_violation_is_denied() -> None:
    argument_schema = {
        "properties": {
            "request": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "metadata": {
                        "type": "object",
                        "properties": {"depth": {"type": "integer"}},
                        "additionalProperties": False,
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            }
        },
        "required": ["request"],
        "additionalProperties": False,
    }
    registration = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read a project file", "mode": "read"},
        argument_schema=argument_schema,
    )
    registry = MCPTrustRegistry([registration])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={
                MCP_CALL_KEY: _call(
                    arguments={
                        "request": {"path": "README.md", "metadata": {"depth": "deep"}}
                    },
                    argument_schema=argument_schema,
                )
            }
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_argument_schema_violation"
    assert "argument 'request.metadata.depth' must be integer" in sig.rationale


def test_array_item_argument_schema_violation_is_denied() -> None:
    argument_schema = {
        "properties": {"paths": {"type": "array", "items": {"type": "string"}}},
        "required": ["paths"],
    }
    registration = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read a project file", "mode": "read"},
        argument_schema=argument_schema,
    )
    registry = MCPTrustRegistry([registration])
    sig = registry.evaluate(
        EvaluationRequest(
            metadata={
                MCP_CALL_KEY: _call(
                    arguments={"paths": ["README.md", 7]},
                    argument_schema=argument_schema,
                )
            }
        )
    )

    assert sig is not None
    assert sig.signal_type == "mcp_argument_schema_violation"
    assert "argument 'paths[1]' must be string" in sig.rationale


def test_array_without_item_schema_is_accepted() -> None:
    argument_schema = {
        "properties": {"paths": {"type": "array"}},
        "required": ["paths"],
    }
    registration = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read project files", "mode": "read"},
        argument_schema=argument_schema,
    )
    registry = MCPTrustRegistry([registration])

    assert (
        registry.evaluate(
            EvaluationRequest(
                metadata={
                    MCP_CALL_KEY: _call(
                        arguments={"paths": ["README.md", 7]},
                        tool_schema=registration.tool_schema,
                        argument_schema=argument_schema,
                    )
                }
            )
        )
        is None
    )


def test_schema_helper_accepts_valid_array_items_and_unknown_types() -> None:
    assert (
        mcp_registry._array_schema_violation(
            ["README.md"],
            {"items": {"type": "string"}},
            "paths",
        )
        == ""
    )
    assert mcp_registry._array_schema_violation(["README.md"], {}, "paths") == ""
    assert mcp_registry._matches_schema_type("value", "unsupported") is False


def test_scalar_json_schema_types_enum_and_const_are_enforced() -> None:
    argument_schema = {
        "properties": {
            "ratio": {"type": "number"},
            "dry_run": {"type": "boolean"},
            "sentinel": {"type": "null"},
            "mode": {"enum": ["read"]},
            "version": {"const": 1},
        },
        "required": ["ratio", "dry_run", "sentinel", "mode", "version"],
    }
    registration = MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "local-fs", "transport": "stdio"},
        tool_schema={"description": "read a project file", "mode": "read"},
        argument_schema=argument_schema,
    )
    registry = MCPTrustRegistry([registration])
    clean = _call(
        arguments={
            "ratio": 0.5,
            "dry_run": False,
            "sentinel": None,
            "mode": "read",
            "version": 1,
        },
        argument_schema=argument_schema,
    )
    bad_enum = _call(
        arguments={
            "ratio": 0.5,
            "dry_run": False,
            "sentinel": None,
            "mode": "write",
            "version": 1,
        },
        argument_schema=argument_schema,
    )
    bad_const = _call(
        arguments={
            "ratio": 0.5,
            "dry_run": False,
            "sentinel": None,
            "mode": "read",
            "version": 2,
        },
        argument_schema=argument_schema,
    )

    assert registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: clean})) is None
    enum_signal = registry.evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: bad_enum}))
    const_signal = registry.evaluate(
        EvaluationRequest(metadata={MCP_CALL_KEY: bad_const})
    )
    assert enum_signal is not None
    assert "enum" in enum_signal.rationale
    assert const_signal is not None
    assert "const" in const_signal.rationale


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
