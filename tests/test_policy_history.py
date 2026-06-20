# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — append-only policy history tests

from __future__ import annotations

import pytest

from director_class_ai.policy import (
    PolicyHistory,
    PolicyRevision,
    Profile,
)


def _profile(**overrides: object) -> Profile:
    base: dict[str, object] = {"name": "staging", "action_block_threshold": 0.3}
    base.update(overrides)
    return Profile(**base)  # type: ignore[arg-type]


def _record(
    history: PolicyHistory, profile: Profile, *, reason: str = "change"
) -> PolicyRevision:
    return history.record(
        profile,
        author="ops@anulum.li",
        created_at="2026-06-20T10:00:00Z",
        reason=reason,
    )


class TestEmptyHistory:
    def test_head_is_none(self) -> None:
        assert PolicyHistory().head is None

    def test_revisions_is_empty_tuple(self) -> None:
        assert PolicyHistory().revisions == ()

    def test_get_raises_on_empty(self) -> None:
        with pytest.raises(KeyError, match="no policy revision"):
            PolicyHistory().get("deadbeef")

    def test_rollback_raises_on_empty(self) -> None:
        with pytest.raises(KeyError, match="no policy revision"):
            PolicyHistory().rollback(
                "deadbeef",
                author="ops@anulum.li",
                created_at="2026-06-20T10:00:00Z",
                reason="restore",
            )


class TestRecord:
    def test_first_record_has_no_parent_and_becomes_head(self) -> None:
        history = PolicyHistory()
        revision = _record(history, _profile())
        assert revision.parent is None
        assert history.head is revision
        assert history.revisions == (revision,)

    def test_second_record_links_parent_to_previous_head(self) -> None:
        history = PolicyHistory()
        first = _record(history, _profile())
        second = _record(history, _profile(action_block_threshold=0.1))
        assert second.parent == first.digest
        assert history.head is second
        assert len(history.revisions) == 2

    def test_revisions_view_is_an_immutable_copy(self) -> None:
        history = PolicyHistory()
        _record(history, _profile())
        snapshot = history.revisions
        _record(history, _profile(content_threshold=0.9))
        assert len(snapshot) == 1
        assert len(history.revisions) == 2


class TestAppendIntegrity:
    def test_append_first_with_parent_is_rejected(self) -> None:
        history = PolicyHistory()
        orphan = PolicyRevision(
            profile=_profile(),
            author="ops@anulum.li",
            created_at="2026-06-20T10:00:00Z",
            reason="orphan",
            parent="not-in-history",
        )
        with pytest.raises(ValueError, match="must not declare a parent"):
            history.append(orphan)

    def test_append_first_without_parent_is_accepted(self) -> None:
        history = PolicyHistory()
        revision = PolicyRevision(
            profile=_profile(),
            author="ops@anulum.li",
            created_at="2026-06-20T10:00:00Z",
            reason="root",
        )
        history.append(revision)
        assert history.head is revision

    def test_append_with_wrong_parent_is_rejected(self) -> None:
        history = PolicyHistory()
        _record(history, _profile())
        forked = PolicyRevision(
            profile=_profile(content_threshold=0.9),
            author="attacker@example.com",
            created_at="2026-06-20T11:00:00Z",
            reason="fork",
            parent="wrong-parent-digest",
        )
        with pytest.raises(ValueError, match="does not match the current head"):
            history.append(forked)

    def test_append_with_correct_parent_is_accepted(self) -> None:
        history = PolicyHistory()
        first = _record(history, _profile())
        nxt = first.child(
            _profile(content_threshold=0.9),
            author="ops@anulum.li",
            created_at="2026-06-20T11:00:00Z",
            reason="tighten",
        )
        history.append(nxt)
        assert history.head is nxt


class TestGet:
    def test_get_returns_earliest_revision_with_digest(self) -> None:
        history = PolicyHistory()
        first = _record(history, _profile())
        assert history.get(first.digest) is first

    def test_get_unknown_digest_raises(self) -> None:
        history = PolicyHistory()
        _record(history, _profile())
        with pytest.raises(KeyError, match="no policy revision"):
            history.get("0" * 64)


class TestRollback:
    def test_rollback_restores_prior_posture_as_new_head(self) -> None:
        history = PolicyHistory()
        baseline = _record(history, _profile(action_block_threshold=0.3))
        _record(history, _profile(action_block_threshold=0.05), reason="too tight")

        restored = history.rollback(
            baseline.digest,
            author="reviewer@anulum.li",
            created_at="2026-06-20T12:00:00Z",
            reason="revert over-tight block threshold",
        )

        assert restored.digest == baseline.digest
        assert history.head is restored
        assert restored.matches(_profile(action_block_threshold=0.3))

    def test_rollback_is_append_only_and_keeps_lineage(self) -> None:
        history = PolicyHistory()
        baseline = _record(history, _profile())
        _record(history, _profile(require_audit=True), reason="relax via audit flag")
        history.rollback(
            baseline.digest,
            author="reviewer@anulum.li",
            created_at="2026-06-20T12:00:00Z",
            reason="restore baseline",
        )
        assert len(history.revisions) == 3
        assert history.head is not None
        assert history.head.parent == history.revisions[1].digest

    def test_rollback_unknown_digest_raises(self) -> None:
        history = PolicyHistory()
        _record(history, _profile())
        with pytest.raises(KeyError, match="no policy revision"):
            history.rollback(
                "f" * 64,
                author="reviewer@anulum.li",
                created_at="2026-06-20T12:00:00Z",
                reason="restore",
            )
