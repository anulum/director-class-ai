# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action plane (effector-boundary kill-switch)

"""Action-plane detectors: govern what an autonomous system *does*, not just says."""

from .blast_radius import BlastRadiusDetector
from .causal_takeover import (
    CAUSAL_TIMELINE_KEY,
    ActionTimeline,
    CausalTakeoverDetector,
)
from .destructive_command import DestructiveCommandDetector
from .intent_consistency import IntentConsistencyDetector
from .mcp_inspector import MCP_CALL_KEY, MCPCallInspector, MCPToolCall, serialise_call
from .mcp_registry import MCPToolRegistration, MCPTrustRegistry
from .origin_taint import OriginTaintDetector
from .reversibility import REVERSIBILITY_KEY, ReversibilityDetector

__all__ = [
    "BlastRadiusDetector",
    "CAUSAL_TIMELINE_KEY",
    "ActionTimeline",
    "CausalTakeoverDetector",
    "DestructiveCommandDetector",
    "IntentConsistencyDetector",
    "MCPCallInspector",
    "MCPToolCall",
    "MCP_CALL_KEY",
    "MCPToolRegistration",
    "MCPTrustRegistry",
    "OriginTaintDetector",
    "REVERSIBILITY_KEY",
    "ReversibilityDetector",
    "serialise_call",
]
