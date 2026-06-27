# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP gateway registry guard tests

from __future__ import annotations

from director_class_ai.action import MCPToolRegistration
from director_class_ai.gateway import MCPGateway, MCPGatewayRequest


def _registration(
    argument_schema: dict[str, object] | None = None,
) -> MCPToolRegistration:
    return MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema=argument_schema or {"properties": {"path": {"type": "string"}}},
    )


def test_nested_argument_schema_violation_blocks_gateway_review() -> None:
    argument_schema: dict[str, object] = {
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
    request = MCPGatewayRequest.from_parts(
        "fs",
        "read_file",
        {"request": {"path": "README.md", "metadata": {"depth": "deep"}}},
        server_identity={"name": "fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema=argument_schema,
    )
    decision = MCPGateway.from_registry([_registration(argument_schema)]).review(request)

    assert decision.route == "block"
    assert decision.firing == ("mcp_argument_schema_violation",)


def test_dynamic_discovery_blocks_cross_server_lookalike_gateway_review() -> None:
    request = MCPGatewayRequest.from_parts(
        "remote-fs",
        "read_fiel",
        {"path": "README.md"},
        server_identity={"name": "remote-fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema={"properties": {"path": {"type": "string"}}},
    )
    decision = MCPGateway.from_registry(
        [_registration()],
        allow_dynamic_discovery=True,
    ).review(request)

    assert decision.route == "block"
    assert decision.firing == ("mcp_lookalike_tool",)
