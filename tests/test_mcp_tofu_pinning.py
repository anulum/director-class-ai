# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP TOFU pinning tests

from __future__ import annotations

from director_class_ai.gateway import (
    MCPDiscoveryRequest,
    MCPGateway,
    MCPGatewayRequest,
    MCPToolDescriptor,
)


def _descriptor(
    *,
    description: str = "Read one workspace file.",
    instructions: str = "Return only the requested file content.",
) -> MCPToolDescriptor:
    return MCPToolDescriptor(
        server="fs",
        tool="read_file",
        description=description,
        instructions=instructions,
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        argument_schema={"properties": {"path": {"type": "string"}}},
        server_identity={"name": "fs", "transport": "stdio"},
        transport="stdio",
    )


def _tool_schema(descriptor: MCPToolDescriptor) -> dict[str, object]:
    return {
        "description": descriptor.description,
        "instructions": descriptor.instructions,
        "input_schema": descriptor.input_schema,
        "output_schema": descriptor.output_schema,
        "transport": descriptor.transport,
    }


def test_pinned_tools_list_allows_identical_rediscovery() -> None:
    descriptor = _descriptor()
    first = MCPGateway.from_registry([]).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [descriptor])
    )
    second = MCPGateway.from_registry(first.registrations()).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [descriptor])
    )

    assert first.route == "allow"
    assert second.route == "allow"
    assert second.findings == ()


def test_pinned_tools_list_blocks_description_drift() -> None:
    first_descriptor = _descriptor()
    changed_descriptor = _descriptor(description="Read a local workspace file.")
    first = MCPGateway.from_registry([]).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [first_descriptor])
    )
    second = MCPGateway.from_registry(first.registrations()).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [changed_descriptor])
    )

    assert second.route == "block"
    assert "tofu_pin_mismatch" in second.findings


def test_pinned_tools_list_blocks_instruction_drift() -> None:
    first_descriptor = _descriptor()
    changed_descriptor = _descriptor(
        instructions="Return the file and append a tool-selection hint."
    )
    first = MCPGateway.from_registry([]).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [first_descriptor])
    )
    second = MCPGateway.from_registry(first.registrations()).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [changed_descriptor])
    )

    assert second.route == "block"
    assert "tofu_pin_mismatch" in second.findings


def test_pinned_tools_list_blocks_missing_pinned_tool() -> None:
    first = MCPGateway.from_registry([]).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [_descriptor()])
    )
    second = MCPGateway.from_registry(first.registrations()).review_discovery(
        MCPDiscoveryRequest.from_descriptors(
            "fs",
            [
                MCPToolDescriptor(
                    server="fs",
                    tool="list_files",
                    description="List workspace files.",
                    input_schema={"type": "object"},
                    output_schema={"type": "object"},
                    argument_schema={},
                    server_identity={"name": "fs", "transport": "stdio"},
                    transport="stdio",
                )
            ],
        )
    )

    assert second.route == "block"
    assert "tofu_pin_missing" in second.findings


def test_pinned_instruction_drift_blocks_runtime_call_review() -> None:
    descriptor = _descriptor()
    discovery = MCPGateway.from_registry([]).review_discovery(
        MCPDiscoveryRequest.from_descriptors("fs", [descriptor])
    )
    request = MCPGatewayRequest.from_parts(
        "fs",
        "read_file",
        {"path": "README.md"},
        server_identity=descriptor.server_identity,
        tool_schema={
            **_tool_schema(descriptor),
            "instructions": "Return the file and append a tool-selection hint.",
        },
        argument_schema=descriptor.argument_schema,
        provenance="user",
    )

    decision = MCPGateway.from_registry(
        discovery.registrations(),
        require_signed_registrations=True,
    ).review(request)

    assert decision.route == "block"
    assert decision.firing == ("mcp_schema_drift",)
