# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval-gated policy change review tests

from __future__ import annotations

import pytest

from director_class_ai.policy import (
    PolicyChangeReview,
    PolicyHistory,
    Profile,
)


def _profile(**overrides: object) -> Profile:
    base: dict[str, object] = {"name": "staging", "action_block_threshold": 0.3}
    base.update(overrides)
    return Profile(**base)  # type: ignore[arg-type]


def _review(seed: Profile | None = None) -> PolicyChangeReview:
    history = PolicyHistory()
    if seed is not None:
        history.record(
            seed,
            author="bootstrap@anulum.li",
            created_at="2026-06-20T09:00:00Z",
            reason="seed baseline posture",
        )
    return PolicyChangeReview(history)


def _propose(review: PolicyChangeReview, profile: Profile, *, proposer: str = "alice"):
    return review.propose(
        profile,
        proposer=proposer,
        created_at="2026-06-20T10:00:00Z",
        reason="tighten action block threshold",
    )


class TestPropose:
    def test_first_proposal_is_parentless_and_pending(self) -> None:
        review = _review()
        proposal = _propose(review, _profile())
        assert proposal.status == "pending"
        assert proposal.revision.parent is None
        assert review.history.head is None  # not committed yet

    def test_subsequent_proposal_bases_on_current_head(self) -> None:
        review = _review(seed=_profile())
        proposal = _propose(review, _profile(action_block_threshold=0.1))
        assert proposal.revision.parent == review.history.head.digest  # type: ignore[union-attr]

    def test_proposing_the_current_posture_is_rejected(self) -> None:
        review = _review(seed=_profile())
        with pytest.raises(ValueError, match="identical to the current head"):
            _propose(review, _profile())

    def test_duplicate_pending_proposal_is_rejected(self) -> None:
        review = _review(seed=_profile())
        _propose(review, _profile(action_block_threshold=0.1))
        with pytest.raises(ValueError, match="already exists"):
            _propose(review, _profile(action_block_threshold=0.1))

    def test_can_re_propose_after_denial(self) -> None:
        review = _review(seed=_profile())
        first = _propose(review, _profile(action_block_threshold=0.1))
        review.deny(first.digest, reviewer="bob", decided_at="2026-06-20T11:00:00Z")
        again = _propose(review, _profile(action_block_threshold=0.1))
        assert again.status == "pending"
        assert again.digest == first.digest


class TestGetAndPending:
    def test_get_returns_proposal(self) -> None:
        review = _review(seed=_profile())
        proposal = _propose(review, _profile(action_block_threshold=0.1))
        assert review.get(proposal.digest) is proposal

    def test_get_unknown_raises(self) -> None:
        with pytest.raises(KeyError, match="no policy change proposal"):
            _review().get("0" * 64)

    def test_pending_lists_only_undecided(self) -> None:
        review = _review(seed=_profile())
        keep = _propose(review, _profile(action_block_threshold=0.1))
        drop = _propose(review, _profile(content_threshold=0.9))
        review.deny(drop.digest, reviewer="bob", decided_at="2026-06-20T11:00:00Z")
        pending = review.pending()
        assert [p.digest for p in pending] == [keep.digest]


class TestApprove:
    def test_approve_commits_proposal_as_head(self) -> None:
        review = _review(seed=_profile())
        proposal = _propose(review, _profile(action_block_threshold=0.1))
        committed = review.approve(
            proposal.digest, reviewer="bob", decided_at="2026-06-20T12:00:00Z"
        )
        assert review.history.head is committed
        assert committed.digest == proposal.digest
        decided = review.get(proposal.digest)
        assert decided.status == "approved"
        assert decided.reviewer == "bob"
        assert decided.decided_at == "2026-06-20T12:00:00Z"

    def test_proposer_cannot_self_approve(self) -> None:
        review = _review(seed=_profile())
        proposal = _propose(
            review, _profile(action_block_threshold=0.1), proposer="alice"
        )
        with pytest.raises(ValueError, match="cannot be approved by its proposer"):
            review.approve(
                proposal.digest, reviewer="alice", decided_at="2026-06-20T12:00:00Z"
            )

    def test_approve_unknown_raises(self) -> None:
        with pytest.raises(KeyError, match="no policy change proposal"):
            _review().approve("0" * 64, reviewer="bob", decided_at="2026-06-20T12:00:00Z")

    def test_approve_already_decided_raises(self) -> None:
        review = _review(seed=_profile())
        proposal = _propose(review, _profile(action_block_threshold=0.1))
        review.approve(proposal.digest, reviewer="bob", decided_at="2026-06-20T12:00:00Z")
        with pytest.raises(ValueError, match="not pending"):
            review.approve(
                proposal.digest, reviewer="bob", decided_at="2026-06-20T13:00:00Z"
            )

    def test_stale_proposal_is_rejected(self) -> None:
        review = _review(seed=_profile())
        stale = _propose(review, _profile(action_block_threshold=0.1))
        # A different change is proposed and approved first, moving the head.
        winner = _propose(review, _profile(content_threshold=0.9))
        review.approve(winner.digest, reviewer="bob", decided_at="2026-06-20T12:00:00Z")
        with pytest.raises(ValueError, match="stale"):
            review.approve(
                stale.digest, reviewer="bob", decided_at="2026-06-20T12:05:00Z"
            )

    def test_first_proposal_goes_stale_if_history_seeded_meanwhile(self) -> None:
        review = _review()
        proposal = _propose(review, _profile())
        review.history.record(
            _profile(content_threshold=0.9),
            author="other@anulum.li",
            created_at="2026-06-20T11:00:00Z",
            reason="direct baseline",
        )
        with pytest.raises(ValueError, match="stale"):
            review.approve(
                proposal.digest, reviewer="bob", decided_at="2026-06-20T12:00:00Z"
            )


class TestDeny:
    def test_deny_does_not_commit(self) -> None:
        review = _review(seed=_profile())
        proposal = _propose(review, _profile(action_block_threshold=0.1))
        denied = review.deny(
            proposal.digest, reviewer="bob", decided_at="2026-06-20T12:00:00Z"
        )
        assert denied.status == "denied"
        assert denied.reviewer == "bob"
        assert len(review.history.revisions) == 1  # only the seed

    def test_deny_unknown_raises(self) -> None:
        with pytest.raises(KeyError, match="no policy change proposal"):
            _review().deny("0" * 64, reviewer="bob", decided_at="2026-06-20T12:00:00Z")

    def test_deny_already_decided_raises(self) -> None:
        review = _review(seed=_profile())
        proposal = _propose(review, _profile(action_block_threshold=0.1))
        review.deny(proposal.digest, reviewer="bob", decided_at="2026-06-20T12:00:00Z")
        with pytest.raises(ValueError, match="not pending"):
            review.deny(
                proposal.digest, reviewer="bob", decided_at="2026-06-20T13:00:00Z"
            )


def test_proposals_returns_all_pending_and_terminal() -> None:
    review = _review(_profile())
    pending = _propose(review, _profile(action_block_threshold=0.5))
    denied = _propose(review, _profile(action_block_threshold=0.6))
    review.deny(denied.digest, reviewer="bob", decided_at="2026-06-20T11:00:00Z")

    by_digest = {p.digest: p.status for p in review.proposals}
    assert by_digest == {pending.digest: "pending", denied.digest: "denied"}


def test_restore_rehydrates_history_and_proposals() -> None:
    review = _review(_profile())
    proposal = _propose(review, _profile(action_block_threshold=0.5))

    restored = PolicyChangeReview.restore(review.history, review.proposals)

    assert restored.history.head is review.history.head
    assert restored.get(proposal.digest).digest == proposal.digest
    assert [p.digest for p in restored.pending()] == [proposal.digest]
