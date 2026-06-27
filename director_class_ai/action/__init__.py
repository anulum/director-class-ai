# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action plane (in-process effector-boundary checkpoint)

"""Action-plane detectors: govern what an autonomous system *does*, not just says."""

from .blast_radius import BlastRadiusDetector
from .browser import (
    BROWSER_ACTION_KEY,
    BrowserAction,
    BrowserActionDetector,
    BrowserWorkLog,
    BrowserWorkLogEntry,
    ComputerAction,
)
from .causal_takeover import (
    CAUSAL_TIMELINE_KEY,
    ActionTimeline,
    CausalTakeoverDetector,
)
from .destructive_command import DestructiveCommandDetector
from .intent_consistency import IntentConsistencyDetector
from .mcp_inspector import MCP_CALL_KEY, MCPCallInspector, MCPToolCall, serialise_call
from .mcp_registry import MCPToolRegistration, MCPTrustRegistry
from .memory import (
    MEMORY_CONTEXT_KEY,
    MemoryActionContext,
    MemoryPlanDelta,
    MemoryThreatDetector,
    MemoryWriteContract,
)
from .origin_taint import OriginTaintDetector
from .remanentia import (
    REMANENTIA_MEMORY_CONTEXT_KEY,
    RemanentiaMemoryGovernanceDetector,
    RemanentiaMemoryOperation,
)
from .reversibility import REVERSIBILITY_KEY, ReversibilityDetector

__all__ = [
    "BlastRadiusDetector",
    "BROWSER_ACTION_KEY",
    "BrowserAction",
    "BrowserActionDetector",
    "BrowserWorkLog",
    "BrowserWorkLogEntry",
    "CAUSAL_TIMELINE_KEY",
    "ComputerAction",
    "ActionTimeline",
    "CausalTakeoverDetector",
    "DestructiveCommandDetector",
    "IntentConsistencyDetector",
    "MCPCallInspector",
    "MCPToolCall",
    "MCP_CALL_KEY",
    "MCPToolRegistration",
    "MCPTrustRegistry",
    "MEMORY_CONTEXT_KEY",
    "MemoryActionContext",
    "MemoryPlanDelta",
    "MemoryThreatDetector",
    "MemoryWriteContract",
    "OriginTaintDetector",
    "REMANENTIA_MEMORY_CONTEXT_KEY",
    "RemanentiaMemoryGovernanceDetector",
    "RemanentiaMemoryOperation",
    "REVERSIBILITY_KEY",
    "ReversibilityDetector",
    "serialise_call",
]
