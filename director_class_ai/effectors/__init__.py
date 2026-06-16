# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — effector boundary

"""Typed effector boundary: govern what an agent *does* before the effector runs it."""

from .mcp import MCPEffectorAdapter, MCPExecuteFn
from .shell import ShellEffectorAdapter
from .subprocess_guard import SubprocessGuard, default_subprocess_runner
from .types import (
    EffectorKind,
    EffectorRequest,
    EffectorResult,
    GovernedEffector,
    ReversibilityMetadata,
)

__all__ = [
    "EffectorKind",
    "EffectorRequest",
    "EffectorResult",
    "GovernedEffector",
    "MCPEffectorAdapter",
    "MCPExecuteFn",
    "ReversibilityMetadata",
    "ShellEffectorAdapter",
    "SubprocessGuard",
    "default_subprocess_runner",
]
