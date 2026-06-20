# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval-gated policy change review

"""Approval-gated review for policy-posture changes.

Guardrail-as-Code, third increment. A :class:`PolicyChangeReview` wraps a
:class:`~director_class_ai.policy.history.PolicyHistory` so a posture change
cannot take effect by being recorded directly: it must be *proposed*, then
*approved* by a different identity before it is committed as the new head.

A proposal is bound to a base — the history head at propose time — so an approval
is never applied against a head that moved underneath it: a stale proposal is
rejected and must be re-proposed against the current head, the same way a code
change is rebased before merge. Denials and approvals record the reviewer and the
decision time, so every posture change carries who proposed it, who reviewed it,
and the outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .history import PolicyHistory
from .profile import Profile
from .revision import PolicyRevision

__all__ = ["PolicyChangeProposal", "PolicyChangeReview"]

PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
_TERMINAL = frozenset({APPROVED, DENIED})


@dataclass(frozen=True)
class PolicyChangeProposal:
    """A proposed posture change awaiting review.

    Attributes
    ----------
    revision : PolicyRevision
        The revision that will be committed if the proposal is approved; its
        parent is the history head at propose time (the proposal's base).
    status : str
        ``"pending"``, ``"approved"``, or ``"denied"``.
    reviewer : str
        Who approved or denied the proposal; empty while pending.
    decided_at : str
        When the decision was recorded (ISO timestamp); empty while pending.
    """

    revision: PolicyRevision
    status: str = PENDING
    reviewer: str = ""
    decided_at: str = ""

    @property
    def digest(self) -> str:
        """Return the content address of the proposed posture."""
        return self.revision.digest


class PolicyChangeReview:
    """Gate posture changes to a history behind proposal and approval."""

    def __init__(self, history: PolicyHistory) -> None:
        """Wrap the history whose changes this review gates."""
        self._history = history
        self._proposals: dict[str, PolicyChangeProposal] = {}

    @property
    def history(self) -> PolicyHistory:
        """Return the gated history."""
        return self._history

    def propose(
        self, profile: Profile, *, proposer: str, created_at: str, reason: str
    ) -> PolicyChangeProposal:
        """Open a pending proposal to change the posture to ``profile``.

        Parameters
        ----------
        profile : Profile
            The proposed governance posture.
        proposer : str
            Who is proposing the change.
        created_at : str
            When the proposal was opened (ISO timestamp).
        reason : str
            Why the posture should change.

        Returns
        -------
        PolicyChangeProposal
            The pending proposal, keyed by the proposed posture's content address.

        Raises
        ------
        ValueError
            If the proposed posture is identical to the current head (a no-op
            change) or a pending proposal already exists for that posture.
        """
        head = self._history.head
        if head is None:
            revision = PolicyRevision(
                profile=profile,
                author=proposer,
                created_at=created_at,
                reason=reason,
            )
        else:
            if head.matches(profile):
                raise ValueError(
                    "proposed posture is identical to the current head; nothing to review"
                )
            revision = head.child(
                profile, author=proposer, created_at=created_at, reason=reason
            )
        existing = self._proposals.get(revision.digest)
        if existing is not None and existing.status == PENDING:
            raise ValueError(
                f"a pending proposal already exists for posture {revision.digest!r}"
            )
        proposal = PolicyChangeProposal(revision=revision)
        self._proposals[revision.digest] = proposal
        return proposal

    def get(self, digest: str) -> PolicyChangeProposal:
        """Return the proposal for ``digest``, or raise ``KeyError``."""
        try:
            return self._proposals[digest]
        except KeyError:
            raise KeyError(f"no policy change proposal for digest {digest!r}") from None

    def pending(self) -> tuple[PolicyChangeProposal, ...]:
        """Return all proposals still awaiting a decision, in proposal order."""
        return tuple(p for p in self._proposals.values() if p.status == PENDING)

    def approve(self, digest: str, *, reviewer: str, decided_at: str) -> PolicyRevision:
        """Approve a pending proposal and commit it as the new head.

        Parameters
        ----------
        digest : str
            The proposed posture's content address.
        reviewer : str
            Who approves the change; must differ from the proposer so a change is
            never self-approved.
        decided_at : str
            When the approval was recorded (ISO timestamp).

        Returns
        -------
        PolicyRevision
            The committed revision, now the head of the gated history.

        Raises
        ------
        KeyError
            If no proposal exists for ``digest``.
        ValueError
            If the proposal is not pending, the reviewer is the proposer, or the
            proposal is stale because the head moved since it was opened.
        """
        proposal = self._require_pending(digest)
        if reviewer == proposal.revision.author:
            raise ValueError("a policy change cannot be approved by its proposer")
        head = self._history.head
        base = head.digest if head is not None else None
        if proposal.revision.parent != base:
            raise ValueError(
                "policy change proposal is stale: the head moved since it was "
                "opened; re-propose against the current head"
            )
        self._history.append(proposal.revision)
        self._proposals[digest] = replace(
            proposal, status=APPROVED, reviewer=reviewer, decided_at=decided_at
        )
        return proposal.revision

    def deny(
        self, digest: str, *, reviewer: str, decided_at: str
    ) -> PolicyChangeProposal:
        """Deny a pending proposal without committing it.

        Parameters
        ----------
        digest : str
            The proposed posture's content address.
        reviewer : str
            Who denies the change.
        decided_at : str
            When the denial was recorded (ISO timestamp).

        Returns
        -------
        PolicyChangeProposal
            The denied proposal.

        Raises
        ------
        KeyError
            If no proposal exists for ``digest``.
        ValueError
            If the proposal is not pending.
        """
        self._require_pending(digest)
        denied = replace(
            self._proposals[digest],
            status=DENIED,
            reviewer=reviewer,
            decided_at=decided_at,
        )
        self._proposals[digest] = denied
        return denied

    def _require_pending(self, digest: str) -> PolicyChangeProposal:
        """Return the pending proposal for ``digest`` or fail."""
        proposal = self.get(digest)
        if proposal.status in _TERMINAL:
            raise ValueError(
                f"policy change proposal {digest!r} is {proposal.status}, not pending"
            )
        return proposal
