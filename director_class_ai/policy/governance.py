# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy governance workflow

"""The operator workflow that ties the Guardrail-as-Code primitives together.

The policy package ships the lifecycle as separate primitives — content-addressed
revisions, an append-only history with rollback, an approval-gated review, an A/B
posture exposure, and a drift monitor. :class:`PolicyGovernance` is the single
durable workflow over them, so an operator can run the lifecycle as a sequence of
commands against one stored ledger:

    propose a candidate posture
      -> expose it A/B against the approved head (see the decision delta)
        -> approve (a different reviewer) or deny the proposal
          -> the approved revision becomes the new head
            -> check a live deployment for drift against that head

The workflow holds no posture of its own: every method delegates to the primitive
that owns the rule (self-approval, lineage integrity, staleness), so the gate is
identical whether a change is driven from the API, the CLI, or a test.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from .drift import PolicyDriftEvent, PolicyDriftMonitor
from .exposure import ExposureCase, ExposureReport, PostureExposure
from .history import PolicyHistory
from .profile import Profile
from .review import PolicyChangeProposal, PolicyChangeReview
from .revision import PolicyRevision
from .store import load_governance, save_governance

__all__ = ["PolicyGovernance"]


class PolicyGovernance:
    """Durable operator workflow over the Guardrail-as-Code primitives."""

    def __init__(self, review: PolicyChangeReview) -> None:
        """Drive the lifecycle through an approval-gated ``review``."""
        self._review = review

    @classmethod
    def empty(cls) -> PolicyGovernance:
        """Start a workflow with no recorded posture and no proposals."""
        return cls(PolicyChangeReview(PolicyHistory()))

    @classmethod
    def load(cls, path: str | Path) -> PolicyGovernance:
        """Load the workflow from ``path``, or start empty if it does not exist.

        Parameters
        ----------
        path : str or Path
            The governance ledger file.

        Returns
        -------
        PolicyGovernance
            The workflow rehydrated from the ledger, or an empty workflow when no
            ledger exists yet.
        """
        if not Path(path).exists():
            return cls.empty()
        history, proposals = load_governance(path)
        return cls(PolicyChangeReview.restore(history, proposals))

    def save(self, path: str | Path) -> None:
        """Write the revision lineage and its proposals to ``path``."""
        save_governance(
            path,
            history=self._review.history,
            proposals=self._review.proposals,
        )

    @property
    def head(self) -> PolicyRevision | None:
        """Return the approved posture in force, or ``None`` when none is set."""
        return self._review.history.head

    def propose(
        self, profile: Profile, *, proposer: str, created_at: str, reason: str
    ) -> PolicyChangeProposal:
        """Open a pending proposal to change the posture to ``profile``."""
        return self._review.propose(
            profile, proposer=proposer, created_at=created_at, reason=reason
        )

    def expose(self, candidate: Profile, cases: Sequence[ExposureCase]) -> ExposureReport:
        """Replay ``cases`` under the approved head and ``candidate`` posture.

        Parameters
        ----------
        candidate : Profile
            The posture being considered.
        cases : sequence of ExposureCase
            The request signal sets to replay.

        Returns
        -------
        ExposureReport
            The decision delta of ``candidate`` against the approved head.

        Raises
        ------
        ValueError
            If no posture has been approved yet, so there is no baseline.
        """
        head = self.head
        if head is None:
            raise ValueError(
                "no approved posture to compare against; record a baseline first"
            )
        return PostureExposure(head.profile, candidate).expose(cases)

    def proposal(self, digest: str) -> PolicyChangeProposal:
        """Return the proposal for ``digest``, or raise ``KeyError``."""
        return self._review.get(digest)

    def pending(self) -> tuple[PolicyChangeProposal, ...]:
        """Return the proposals still awaiting a decision."""
        return self._review.pending()

    def approve(self, digest: str, *, reviewer: str, decided_at: str) -> PolicyRevision:
        """Approve a pending proposal, committing it as the new head."""
        return self._review.approve(digest, reviewer=reviewer, decided_at=decided_at)

    def deny(
        self, digest: str, *, reviewer: str, decided_at: str
    ) -> PolicyChangeProposal:
        """Deny a pending proposal without committing it."""
        return self._review.deny(digest, reviewer=reviewer, decided_at=decided_at)

    def rollback(
        self, digest: str, *, author: str, created_at: str, reason: str
    ) -> PolicyRevision:
        """Restore a prior posture by appending it as the new head."""
        return self._review.history.rollback(
            digest, author=author, created_at=created_at, reason=reason
        )

    def drift_check(
        self,
        live: Profile,
        *,
        detected_at: str,
        sink: Callable[[PolicyDriftEvent], None] | None = None,
    ) -> PolicyDriftEvent | None:
        """Check a live posture for drift against the approved head.

        Parameters
        ----------
        live : Profile
            The profile a deployment is currently running.
        detected_at : str
            When the check was run (ISO timestamp).
        sink : callable, optional
            Receives the drift event when the live posture diverges.

        Returns
        -------
        PolicyDriftEvent or None
            The drift event when ``live`` diverges from the approved head;
            ``None`` when it still matches.

        Raises
        ------
        ValueError
            If no posture has been approved yet.
        """
        head = self.head
        if head is None:
            raise ValueError("no approved posture to check drift against")
        return PolicyDriftMonitor(head, sink=sink).check(live, detected_at=detected_at)

    def status(self) -> dict[str, object]:
        """Return a summary of the head, lineage length, and pending proposals."""
        head = self.head
        return {
            "head_digest": head.digest if head is not None else None,
            "head_profile": head.profile.name if head is not None else None,
            "revisions": len(self._review.history.revisions),
            "pending": len(self._review.pending()),
        }
