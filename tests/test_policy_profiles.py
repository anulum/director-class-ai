# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy profile tests

from __future__ import annotations

from pathlib import Path

import pytest

from director_class_ai.policy import Profile, load_profile, load_profile_file

_CONFIGS = Path(__file__).resolve().parent.parent / "configs"
_BUILTINS = ["local_dev", "ci", "pilot", "high_risk"]


@pytest.mark.parametrize("name", _BUILTINS)
def test_builtin_profiles_load_and_default_to_dry_run(name: str) -> None:
    profile = load_profile_file(_CONFIGS / f"{name}.toml")
    assert profile.name == name
    assert profile.default_dry_run is True  # no profile executes by default


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


def test_strict_profile_without_requirements_fails_fast() -> None:
    with pytest.raises(ValueError, match="require_audit and require_approval"):
        load_profile({"name": "pilot", "require_audit": False})


def test_to_fusion_policy_maps_thresholds() -> None:
    profile = load_profile_file(_CONFIGS / "high_risk.toml")
    policy = profile.to_fusion_policy()
    assert policy.action_block_threshold == profile.action_block_threshold
    assert policy.content_threshold == profile.content_threshold


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
    assert {"name", "default_dry_run", "action_block_threshold"} <= Profile.field_names()
