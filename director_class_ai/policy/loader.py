# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy profile loader

"""Load and validate deployment profiles from TOML, failing fast on mistakes.

Unknown keys are rejected (a typo'd threshold must not silently fall back to a
default), and the named-environment invariants are enforced — ``pilot`` and
``high_risk`` must require audit and approval — so a profile cannot be relaxed by
omission.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from .capability_profiles import load_capability_profile
from .profile import Profile

__all__ = ["load_profile", "load_profile_file"]

_STRICT_PROFILES = {"pilot", "high_risk"}


def load_profile(data: dict[str, Any]) -> Profile:
    """Build a Profile from a dict, rejecting unknown keys and weak postures."""
    unknown = set(data) - Profile.field_names()
    if unknown:
        raise ValueError(f"unknown profile keys: {sorted(unknown)}")
    if "name" not in data:
        raise ValueError("profile must declare a name")
    profile = Profile(**data)
    if profile.name in _STRICT_PROFILES and not (
        profile.require_audit and profile.require_approval
    ):
        raise ValueError(
            f"profile {profile.name!r} must set require_audit and require_approval"
        )
    load_capability_profile(profile.capability_profile)
    return profile


def load_profile_file(path: str | Path) -> Profile:
    """Load and validate one TOML profile file."""
    with Path(path).open("rb") as fh:
        return load_profile(tomllib.load(fh))
