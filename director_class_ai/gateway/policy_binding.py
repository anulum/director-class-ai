# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP gateway policy binding

"""Bind Guardrail-as-Code governance state into MCP gateway factories."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from ..action import MCPToolRegistration
from ..core.governor import ApprovalHook, AuditSink
from ..policy import CapabilityGrant, PolicyGovernance
from .mcp import MCPGateway

__all__ = ["gateway_from_governance", "gateway_from_policy_store"]


def gateway_from_governance(
    gateway_cls: type[MCPGateway],
    registrations: Sequence[MCPToolRegistration],
    governance: PolicyGovernance,
    *,
    capability_grants: Sequence[CapabilityGrant] = (),
    allow_dynamic_discovery: bool = False,
    require_signed_registrations: bool = False,
    approval: ApprovalHook | None = None,
    audit_sink: AuditSink | None = None,
) -> MCPGateway:
    """Create an MCP gateway governed by an approved policy head."""
    return gateway_cls.from_registry(
        registrations,
        allow_dynamic_discovery=allow_dynamic_discovery,
        require_signed_registrations=require_signed_registrations,
        fusion_policy=governance.active_fusion_policy(),
        capability_policy=governance.active_capability_policy(grants=capability_grants),
        approval=approval,
        audit_sink=audit_sink,
    )


def gateway_from_policy_store(
    gateway_cls: type[MCPGateway],
    registrations: Sequence[MCPToolRegistration],
    policy_store: str | Path,
    *,
    capability_grants: Sequence[CapabilityGrant] = (),
    allow_dynamic_discovery: bool = False,
    require_signed_registrations: bool = False,
    approval: ApprovalHook | None = None,
    audit_sink: AuditSink | None = None,
) -> MCPGateway:
    """Create an MCP gateway from a persisted Guardrail-as-Code ledger."""
    return gateway_from_governance(
        gateway_cls,
        registrations,
        PolicyGovernance.load(policy_store),
        capability_grants=capability_grants,
        allow_dynamic_discovery=allow_dynamic_discovery,
        require_signed_registrations=require_signed_registrations,
        approval=approval,
        audit_sink=audit_sink,
    )
