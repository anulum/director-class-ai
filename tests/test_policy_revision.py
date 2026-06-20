# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — content-addressed policy revision tests

from __future__ import annotations

import hashlib
import json

import pytest

from director_class_ai.policy import (
    PolicyFieldChange,
    PolicyRevision,
    Profile,
    diff_profiles,
)


def _profile(**overrides: object) -> Profile:
    base: dict[str, object] = {"name": "staging", "action_block_threshold": 0.3}
    base.update(overrides)
    return Profile(**base)  # type: ignore[arg-type]


def _revision(profile: Profile | None = None, **overrides: object) -> PolicyRevision:
    base: dict[str, object] = {
        "profile": profile if profile is not None else _profile(),
        "author": "ops@anulum.li",
        "created_at": "2026-06-20T10:00:00Z",
        "reason": "tighten staging action block threshold",
    }
    base.update(overrides)
    return PolicyRevision(**base)  # type: ignore[arg-type]


class TestDiffProfiles:
    def test_identical_profiles_have_no_changes(self) -> None:
        assert diff_profiles(_profile(), _profile()) == ()

    def test_single_field_change_is_reported(self) -> None:
        changes = diff_profiles(_profile(), _profile(action_block_threshold=0.2))
        assert changes == (
            PolicyFieldChange(field="action_block_threshold", old=0.3, new=0.2),
        )

    def test_multiple_changes_are_ordered_by_field_name(self) -> None:
        changes = diff_profiles(
            _profile(),
            _profile(require_audit=True, content_threshold=0.9),
        )
        assert [change.field for change in changes] == [
            "content_threshold",
            "require_audit",
        ]
        assert changes[0].old == 0.5 and changes[0].new == 0.9
        assert changes[1].old is False and changes[1].new is True

    def test_capability_profile_change_is_reported(self) -> None:
        changes = diff_profiles(
            _profile(),
            _profile(capability_profile="read_only_actions"),
        )
        assert changes == (
            PolicyFieldChange(
                field="capability_profile",
                old="deny_all_actions",
                new="read_only_actions",
            ),
        )


class TestPolicyRevisionValidation:
    def test_valid_revision_is_accepted(self) -> None:
        revision = _revision()
        assert revision.parent is None
        assert revision.author == "ops@anulum.li"

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_author_is_rejected(self, blank: str) -> None:
        with pytest.raises(ValueError, match="non-empty author"):
            _revision(author=blank)

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_created_at_is_rejected(self, blank: str) -> None:
        with pytest.raises(ValueError, match="created_at timestamp"):
            _revision(created_at=blank)

    @pytest.mark.parametrize("blank", ["", "   "])
    def test_blank_reason_is_rejected(self, blank: str) -> None:
        with pytest.raises(ValueError, match="non-empty reason"):
            _revision(reason=blank)


class TestPolicyRevisionDigest:
    def test_digest_matches_canonical_sha256(self) -> None:
        profile = _profile()
        payload = {name: getattr(profile, name) for name in Profile.field_names()}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert _revision(profile).digest == expected

    def test_digest_is_content_addressed_not_metadata_addressed(self) -> None:
        profile = _profile()
        first = _revision(profile, author="alice@anulum.li", reason="initial")
        second = _revision(
            profile,
            author="bob@anulum.li",
            created_at="2026-06-21T00:00:00Z",
            reason="re-approve identical posture",
        )
        assert first.digest == second.digest

    def test_different_posture_yields_different_digest(self) -> None:
        loose = _revision(_profile(action_block_threshold=0.3))
        tight = _revision(_profile(action_block_threshold=0.1))
        assert loose.digest != tight.digest


class TestPolicyRevisionDiffDriftMatch:
    def test_diff_between_revisions(self) -> None:
        old = _revision(_profile(content_threshold=0.5))
        new = _revision(_profile(content_threshold=0.8))
        assert old.diff(new) == (
            PolicyFieldChange(field="content_threshold", old=0.5, new=0.8),
        )

    def test_drift_is_empty_when_live_matches_approved(self) -> None:
        approved = _revision()
        assert approved.drift(_profile()) == ()

    def test_drift_reports_relaxed_live_posture(self) -> None:
        approved = _revision(_profile(require_approval=True))
        drift = approved.drift(_profile(require_approval=False))
        assert drift == (
            PolicyFieldChange(field="require_approval", old=True, new=False),
        )

    def test_matches_true_for_identical_posture(self) -> None:
        assert _revision().matches(_profile()) is True

    def test_matches_false_for_drifted_posture(self) -> None:
        assert _revision().matches(_profile(action_block_threshold=0.9)) is False


class TestPolicyRevisionChild:
    def test_child_links_parent_digest_and_records_metadata(self) -> None:
        parent = _revision()
        child = parent.child(
            _profile(action_block_threshold=0.1),
            author="reviewer@anulum.li",
            created_at="2026-06-20T12:00:00Z",
            reason="approve tighter block threshold",
        )
        assert child.parent == parent.digest
        assert child.author == "reviewer@anulum.li"
        assert child.reason == "approve tighter block threshold"
        assert child.digest != parent.digest

    def test_child_validation_still_applies(self) -> None:
        with pytest.raises(ValueError, match="non-empty reason"):
            _revision().child(
                _profile(),
                author="reviewer@anulum.li",
                created_at="2026-06-20T12:00:00Z",
                reason="",
            )
