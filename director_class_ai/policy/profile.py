# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — deployment policy profiles

"""Named deployment profiles: one safe, validated knob-set per environment.

A profile fixes the governance posture for an environment so it cannot be set
wrong by accident: dry-run is the default everywhere, and a profile that demands
durable evidence (``pilot``, ``high_risk``) refuses to run without an audit sink
and an approval workflow wired. The profile maps to a :class:`FusionPolicy` and
carries the runtime requirements the wiring must satisfy.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from ..core.fusion import FusionPolicy
from .capability import CapabilityGrant, CapabilityPolicy
from .capability_profiles import load_capability_profile

__all__ = ["Profile"]


@dataclass(frozen=True)
class Profile:
    """A validated governance posture for one environment."""

    name: str
    default_dry_run: bool = True
    content_threshold: float = 0.5
    integrity_threshold: float = 0.5
    action_block_threshold: float = 0.3
    uncertainty_margin: float = 0.15
    require_audit: bool = False
    require_approval: bool = False
    capability_profile: str = "deny_all_actions"

    def __post_init__(self) -> None:
        for attr in (
            "content_threshold",
            "integrity_threshold",
            "action_block_threshold",
            "uncertainty_margin",
        ):
            value = getattr(self, attr)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{attr} must be in [0, 1], got {value}")

    def to_fusion_policy(self) -> FusionPolicy:
        """Convert this deployment profile into a fusion policy."""
        return FusionPolicy(
            content_threshold=self.content_threshold,
            integrity_threshold=self.integrity_threshold,
            action_block_threshold=self.action_block_threshold,
            uncertainty_margin=self.uncertainty_margin,
        )

    def to_capability_policy(
        self,
        grants: tuple[CapabilityGrant, ...] = (),
    ) -> CapabilityPolicy:
        """Compile the profile's capability envelope with runtime grants."""
        return load_capability_profile(self.capability_profile).compile(grants)

    def require_runtime(
        self, *, audit_sink: object | None, approval: object | None
    ) -> None:
        """Fail fast if the profile's durability requirements are not wired."""
        if self.require_audit and audit_sink is None:
            raise ValueError(
                f"profile {self.name!r} requires an audit sink, none was provided"
            )
        if self.require_approval and approval is None:
            raise ValueError(
                f"profile {self.name!r} requires an approval workflow, none was provided"
            )

    @classmethod
    def field_names(cls) -> set[str]:
        """Return valid TOML keys for profile loading."""
        return {f.name for f in fields(cls)}
