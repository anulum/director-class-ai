# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy profile tests

from __future__ import annotations

from pathlib import Path

import pytest

from director_class_ai.core import Plane
from director_class_ai.policy import (
    ACTION_SURFACES,
    BUILTIN_CAPABILITY_PROFILES,
    BlastRadius,
    CapabilityContext,
    CapabilityGrant,
    Profile,
    load_profile,
    load_profile_file,
)

_CONFIGS = Path(__file__).resolve().parent.parent / "configs"
_BUILTINS = ["local_dev", "ci", "pilot", "high_risk"]


@pytest.mark.parametrize("name", _BUILTINS)
def test_builtin_profiles_load_and_default_to_dry_run(name: str) -> None:
    profile = load_profile_file(_CONFIGS / f"{name}.toml")
    assert profile.name == name
    assert profile.default_dry_run is True  # no profile executes by default
    assert profile.capability_profile in BUILTIN_CAPABILITY_PROFILES


@pytest.mark.parametrize("name", ["pilot", "high_risk"])
def test_strict_profiles_require_audit_and_approval(name: str) -> None:
    profile = load_profile_file(_CONFIGS / f"{name}.toml")
    assert profile.require_audit is True and profile.require_approval is True


def test_unknown_key_fails_fast() -> None:
    with pytest.raises(ValueError, match="unknown profile keys"):
        load_profile({"name": "x", "blcok_threshold": 0.3})  # typo


def test_missing_name_fails_fast() -> None:
    with pytest.raises(ValueError, match="name"):
        load_profile({"default_dry_run": True})


def test_out_of_range_threshold_fails_fast() -> None:
    with pytest.raises(ValueError, match="action_block_threshold"):
        load_profile({"name": "x", "action_block_threshold": 1.5})


def test_out_of_range_per_plane_margin_fails_fast() -> None:
    with pytest.raises(ValueError, match="content_uncertainty_margin"):
        load_profile({"name": "x", "content_uncertainty_margin": -0.1})


def test_strict_profile_without_requirements_fails_fast() -> None:
    with pytest.raises(ValueError, match="require_audit and require_approval"):
        load_profile({"name": "pilot", "require_audit": False})


def test_unknown_capability_profile_fails_fast() -> None:
    with pytest.raises(ValueError, match="unknown capability profile"):
        load_profile({"name": "x", "capability_profile": "missing"})


def test_to_fusion_policy_maps_thresholds() -> None:
    profile = load_profile_file(_CONFIGS / "high_risk.toml")
    policy = profile.to_fusion_policy()
    assert policy.action_block_threshold == profile.action_block_threshold
    assert policy.content_threshold == profile.content_threshold


def test_to_fusion_policy_maps_per_plane_uncertainty_margins() -> None:
    profile = load_profile(
        {
            "name": "staging",
            "uncertainty_margin": 0.05,
            "content_uncertainty_margin": 0.1,
            "integrity_uncertainty_margin": 0.2,
            "action_uncertainty_margin": 0.0,
        }
    )
    policy = profile.to_fusion_policy()

    assert policy.uncertainty_margin_for(Plane.CONTENT) == 0.1
    assert policy.uncertainty_margin_for(Plane.INTEGRITY) == 0.2
    assert policy.uncertainty_margin_for(Plane.ACTION) == 0.0
    assert policy.content_uncertainty_margin == 0.1
    assert policy.integrity_uncertainty_margin == 0.2
    assert policy.action_uncertainty_margin == 0.0


def test_capability_profiles_cover_required_action_surfaces() -> None:
    expected = {
        "shell",
        "filesystem",
        "database",
        "cloud",
        "kubernetes",
        "email",
        "browser",
        "mcp",
        "external_http",
    }

    assert {surface.value for surface in ACTION_SURFACES} == expected
    for profile in BUILTIN_CAPABILITY_PROFILES.values():
        assert set(profile.surface_names()) == expected


def test_deny_all_capability_profile_rejects_even_matching_grants() -> None:
    policy = load_profile_file(_CONFIGS / "ci.toml").to_capability_policy(
        (_grant(action="execute"),)
    )

    decision = policy.evaluate(_context(action="execute"))

    assert decision.permitted is False
    assert decision.findings == ("origin_not_allowed",)


def test_local_operator_profile_requires_grant_then_origin_match() -> None:
    profile = load_profile_file(_CONFIGS / "local_dev.toml")

    without_grant = profile.to_capability_policy().evaluate(_context(action="execute"))
    with_grant = profile.to_capability_policy((_grant(action="execute"),)).evaluate(
        _context(action="execute")
    )
    wrong_origin = profile.to_capability_policy(
        (_grant(action="execute", source_origin="retrieved"),)
    ).evaluate(_context(action="execute", source_origin="retrieved"))

    assert without_grant.findings == ("capability_missing",)
    assert with_grant.permitted is True
    assert wrong_origin.findings == ("origin_not_allowed",)


class TestRequireRuntime:
    def test_pilot_without_audit_sink_fails_fast(self) -> None:
        p = load_profile_file(_CONFIGS / "pilot.toml")
        with pytest.raises(ValueError, match="audit sink"):
            p.require_runtime(audit_sink=None, approval=lambda *_: True)

    def test_pilot_without_approval_fails_fast(self) -> None:
        p = load_profile_file(_CONFIGS / "pilot.toml")
        with pytest.raises(ValueError, match="approval"):
            p.require_runtime(audit_sink=object(), approval=None)

    def test_pilot_fully_wired_passes(self) -> None:
        p = load_profile_file(_CONFIGS / "pilot.toml")
        p.require_runtime(audit_sink=object(), approval=lambda *_: True)  # no raise

    def test_local_dev_needs_no_sinks(self) -> None:
        p = load_profile_file(_CONFIGS / "local_dev.toml")
        p.require_runtime(audit_sink=None, approval=None)  # no raise


def test_field_names_includes_thresholds() -> None:
    assert {
        "name",
        "default_dry_run",
        "action_block_threshold",
        "action_uncertainty_margin",
        "capability_profile",
    } <= Profile.field_names()


def _context(**overrides: object) -> CapabilityContext:
    base: dict[str, object] = {
        "subject": "agent-a",
        "tenant": "tenant-a",
        "session": "session-a",
        "source_origin": "user",
        "tool": "shell/run",
        "resource": "workspace",
        "action": "execute",
        "blast_radius": "high",
        "now": 10,
    }
    base.update(overrides)
    return CapabilityContext.from_mapping(base)


def _grant(**overrides: object) -> CapabilityGrant:
    base: dict[str, object] = {
        "grant_id": "grant-action",
        "subject": "agent-a",
        "tenant": "tenant-a",
        "session": "session-a",
        "source_origin": "user",
        "tool": "shell/run",
        "resource": "workspace",
        "action": "execute",
        "max_blast_radius": BlastRadius.HIGH,
        "expires_at": 20,
    }
    base.update(overrides)
    return CapabilityGrant(**base)  # type: ignore[arg-type]
