# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — deployable governance gateways

"""Deployable gateway contracts around Director-Class AI governance primitives."""

from .mcp import (
    MCPDiscoveryDecision,
    MCPDiscoveryRequest,
    MCPGateway,
    MCPGatewayDecision,
    MCPGatewayRequest,
    MCPGatewayRoute,
    MCPResponseDecision,
    MCPResponseRequest,
    MCPToolDescriptor,
)

__all__ = [
    "MCPDiscoveryDecision",
    "MCPDiscoveryRequest",
    "MCPGateway",
    "MCPGatewayDecision",
    "MCPGatewayRequest",
    "MCPGatewayRoute",
    "MCPResponseDecision",
    "MCPResponseRequest",
    "MCPToolDescriptor",
]
