# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — capability policy profiles

"""Built-in deny-by-default capability profiles for action surfaces.

Deployment profiles choose one named capability profile. The capability profile
does not grant runtime power by itself; it supplies the allowed origin envelope
for action surfaces. A runtime action still needs a matching
``CapabilityGrant`` before ``CapabilityPolicy`` can permit it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from .capability import CapabilityGrant, CapabilityPolicy, OriginRule

__all__ = [
    "ACTION_SURFACES",
    "BUILTIN_CAPABILITY_PROFILES",
    "ActionSurface",
    "CapabilitySurfaceProfile",
    "load_capability_profile",
]


class ActionSurface(StrEnum):
    """Action surfaces governed by built-in capability profiles."""

    SHELL = "shell"
    FILESYSTEM = "filesystem"
    DATABASE = "database"
    CLOUD = "cloud"
    KUBERNETES = "kubernetes"
    EMAIL = "email"
    BROWSER = "browser"
    MCP = "mcp"
    EXTERNAL_HTTP = "external_http"


ACTION_SURFACES: tuple[ActionSurface, ...] = tuple(ActionSurface)


@dataclass(frozen=True)
class CapabilitySurfaceProfile:
    """Named origin envelope for capability-governed action surfaces."""

    name: str
    surfaces: tuple[ActionSurface, ...]
    origin_rules: tuple[OriginRule, ...] = ()
    baseline_grants: tuple[CapabilityGrant, ...] = ()

    def compile(
        self,
        grants: Sequence[CapabilityGrant] = (),
    ) -> CapabilityPolicy:
        """Build a capability policy from profile rules plus runtime grants."""
        return CapabilityPolicy(
            grants=(*self.baseline_grants, *tuple(grants)),
            origin_rules=self.origin_rules,
        )

    def surface_names(self) -> tuple[str, ...]:
        """Return stable surface names for audits and config tests."""
        return tuple(surface.value for surface in self.surfaces)


def load_capability_profile(name: str) -> CapabilitySurfaceProfile:
    """Return a built-in capability profile by name."""
    try:
        return BUILTIN_CAPABILITY_PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown capability profile: {name!r}") from exc


def _user_origin_rules() -> tuple[OriginRule, ...]:
    return (
        OriginRule("user", action="execute"),
        OriginRule("user", action="read"),
        OriginRule("user", action="write"),
        OriginRule("user", action="delete"),
        OriginRule("user", action="query"),
        OriginRule("user", action="deploy"),
        OriginRule("user", action="scale"),
        OriginRule("user", action="send"),
        OriginRule("user", action="browse"),
        OriginRule("user", action="call"),
        OriginRule("user", action="request"),
    )


BUILTIN_CAPABILITY_PROFILES: Mapping[str, CapabilitySurfaceProfile] = {
    "deny_all_actions": CapabilitySurfaceProfile(
        name="deny_all_actions",
        surfaces=ACTION_SURFACES,
        origin_rules=(OriginRule("__deny_all__"),),
    ),
    "local_operator_actions": CapabilitySurfaceProfile(
        name="local_operator_actions",
        surfaces=ACTION_SURFACES,
        origin_rules=_user_origin_rules(),
    ),
}
