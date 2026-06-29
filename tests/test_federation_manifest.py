# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — schema-A GOVERN-layer federation manifest tests

"""Tests for the GOVERN-layer schema-A studio capability manifest producer.

Covers the action-governance verb set and its honest tiers (runtime control is
production, the real-executor actuate is certified + live-hardware, comparative
benchmark and external certification are research per the bounded claim-language),
the full schema-A key surface, deterministic content-digest semantics (stable,
sha256-prefixed, excludes the environment version, moves on a contract change),
sorted/de-duplicated evidence types, the verb and ui_module renderings, and the
not-installed version fallback.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from importlib.metadata import PackageNotFoundError

import pytest

from director_class_ai.federation import StudioManifest, Verb, build_manifest
from director_class_ai.federation import manifest as manifest_mod


def _section(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    """Return a nested mapping field of a manifest payload, asserting its type."""
    value = payload[key]
    assert isinstance(value, Mapping), f"{key} is not a mapping: {type(value)!r}"
    return value


_SCHEMA_A_KEYS = {
    "contract_era",
    "protocol_version",
    "transport_profile",
    "studio",
    "studio_version",
    "platform_sdk",
    "enumeration",
    "evidence_types",
    "verbs",
    "ui_module",
    "content_digest",
}


def test_build_manifest_govern_verbs_and_panel() -> None:
    manifest = build_manifest()
    verbs = {v.verb for v in manifest.verbs}
    assert verbs == {
        "gate",
        "assess",
        "approve",
        "audit",
        "detect",
        "actuate",
        "certify",
        "benchmark",
    }
    assert manifest.ui_module.exposes == ("./DirectorClassStudioPanel",)
    assert build_manifest().to_dict()["studio"] == "director-class-ai"


def test_honest_tiers_and_side_effects() -> None:
    """Runtime control is production; the real executor is certified+live-hardware.

    Comparative benchmark advantage and external certification are blocked claims
    in positioning.py, so those verbs are honestly research, never production.
    """
    by_verb = {v.verb: v for v in build_manifest().verbs}
    assert by_verb["gate"].safety_tier == "production"
    assert by_verb["audit"].safety_tier == "production"
    actuate = by_verb["actuate"]
    assert actuate.safety_tier == "certified"
    assert actuate.side_effect == "live-hardware"
    assert by_verb["benchmark"].safety_tier == "research"
    assert by_verb["certify"].safety_tier == "research"


def test_only_actuate_has_live_side_effect() -> None:
    """Exactly one verb carries the hub-gated live-hardware side effect (§2.3)."""
    live = [v.verb for v in build_manifest().verbs if v.side_effect == "live-hardware"]
    assert live == ["actuate"]


def test_to_dict_schema_a_surface() -> None:
    payload = build_manifest().to_dict()
    assert set(payload) == _SCHEMA_A_KEYS
    assert payload["contract_era"] == "v1"
    assert payload["transport_profile"] == "local-first"
    assert payload["studio"] == "director-class-ai"
    assert payload["enumeration"] == "language-agnostic"
    assert _section(payload, "ui_module")["remote_entry"] == "/studio/remoteEntry.js"


def test_evidence_types_sorted_and_deduplicated() -> None:
    manifest = build_manifest()
    et = manifest.evidence_types
    assert list(et) == sorted(et)
    assert len(et) == len(set(et))
    produced = {schema for v in manifest.verbs for schema in v.produces}
    assert set(et) == produced


def test_content_digest_is_deterministic_and_prefixed() -> None:
    manifest = build_manifest()
    digest = manifest.content_digest()
    assert digest == build_manifest().content_digest()
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)


def test_content_digest_excludes_studio_version() -> None:
    base = build_manifest()
    bumped = dataclasses.replace(base, studio_version="99.99.99")
    assert bumped.content_digest() == base.content_digest()
    assert bumped.to_dict()["studio_version"] == "99.99.99"


def test_content_digest_moves_when_contract_changes() -> None:
    base = build_manifest()
    fewer = dataclasses.replace(base, verbs=base.verbs[:-1])
    assert fewer.content_digest() != base.content_digest()


def test_verb_to_dict_with_and_without_fidelity() -> None:
    with_fid = Verb(
        verb="assess",
        safety_tier="production",
        side_effect="read-only",
        timing_class="interactive",
        produces=("studio.action-risk.v1",),
        backends=("python", "rust"),
        fidelity="analytic",
    ).to_dict()
    assert with_fid["fidelity"] == "analytic"
    assert with_fid["timing"] == {"class": "interactive"}

    without_fid = Verb(
        verb="actuate",
        safety_tier="certified",
        side_effect="live-hardware",
        timing_class="realtime",
        produces=("studio.action-execution.v1",),
        backends=("python",),
    ).to_dict()
    assert "fidelity" not in without_fid


def test_ui_module_render() -> None:
    assert build_manifest().ui_module.to_dict() == {
        "remote_entry": "/studio/remoteEntry.js",
        "exposes": ["./DirectorClassStudioPanel"],
        "federation": "module-federation-2",
    }


def test_studio_version_from_installed_distribution() -> None:
    assert isinstance(build_manifest().studio_version, str)
    assert build_manifest().studio_version != ""


def test_studio_version_fallback_when_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise(_name: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr(manifest_mod, "version", _raise)
    assert manifest_mod._studio_version() == "0+unknown"


def test_manifest_is_frozen() -> None:
    manifest = build_manifest()
    with pytest.raises(dataclasses.FrozenInstanceError):
        manifest.studio_version = "x"  # type: ignore[misc]


def test_public_surface_reexports() -> None:
    from director_class_ai.federation import UiModule

    assert isinstance(build_manifest(), StudioManifest)
    assert UiModule is manifest_mod.UiModule
