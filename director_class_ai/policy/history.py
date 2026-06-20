# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — append-only policy revision history

"""Append-only policy revision history with lineage integrity and rollback.

Guardrail-as-Code, second increment. A :class:`PolicyHistory` is the ordered,
append-only lineage of :class:`~director_class_ai.policy.revision.PolicyRevision`
records for one environment. Each appended revision must name the current head as
its parent, so a fork, a reorder, or a tampered parent digest is rejected at the
boundary rather than silently governing live actions.

Rollback never deletes history: restoring a prior posture appends a new revision
carrying the target posture's content, so the head's content address again equals
the target's digest while the full lineage — including the relaxation that was
rolled back — stays on the record for audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .profile import Profile
from .revision import PolicyRevision

__all__ = ["PolicyHistory"]


@dataclass
class PolicyHistory:
    """An append-only lineage of policy revisions with rollback by content."""

    _revisions: list[PolicyRevision] = field(default_factory=list)

    @property
    def head(self) -> PolicyRevision | None:
        """Return the most recent revision, or ``None`` when the history is empty."""
        return self._revisions[-1] if self._revisions else None

    @property
    def revisions(self) -> tuple[PolicyRevision, ...]:
        """Return the full lineage in append order as an immutable view."""
        return tuple(self._revisions)

    def append(self, revision: PolicyRevision) -> None:
        """Append a revision, enforcing parent-to-head lineage integrity.

        Parameters
        ----------
        revision : PolicyRevision
            The revision to add.

        Raises
        ------
        ValueError
            If the first revision declares a parent, or a later revision's parent
            does not match the current head's digest (a fork or tampered parent).
        """
        head = self.head
        if head is None:
            if revision.parent is not None:
                raise ValueError(
                    "first policy revision must not declare a parent, "
                    f"got {revision.parent!r}"
                )
        elif revision.parent != head.digest:
            raise ValueError(
                "policy revision parent does not match the current head: "
                f"expected {head.digest!r}, got {revision.parent!r}"
            )
        self._revisions.append(revision)

    def record(
        self, profile: Profile, *, author: str, created_at: str, reason: str
    ) -> PolicyRevision:
        """Build the next revision from ``profile`` and append it.

        The new revision's parent is the current head's digest (or ``None`` for
        the first record), so a recorded change always satisfies lineage
        integrity.

        Parameters
        ----------
        profile : Profile
            The governance posture to record.
        author : str
            Who recorded the change.
        created_at : str
            When the change was recorded (ISO timestamp).
        reason : str
            Why the posture changed.

        Returns
        -------
        PolicyRevision
            The appended revision, now the head of the history.
        """
        head = self.head
        if head is None:
            revision = PolicyRevision(
                profile=profile,
                author=author,
                created_at=created_at,
                reason=reason,
            )
        else:
            revision = head.child(
                profile, author=author, created_at=created_at, reason=reason
            )
        self.append(revision)
        return revision

    def get(self, digest: str) -> PolicyRevision:
        """Return the earliest revision whose content address equals ``digest``.

        Parameters
        ----------
        digest : str
            The content address to look up.

        Returns
        -------
        PolicyRevision
            The first recorded revision carrying that posture (a rolled-back
            posture recurs in the lineage with the same digest).

        Raises
        ------
        KeyError
            If no revision in the history has that digest.
        """
        for revision in self._revisions:
            if revision.digest == digest:
                return revision
        raise KeyError(f"no policy revision with digest {digest!r}")

    def rollback(
        self, digest: str, *, author: str, created_at: str, reason: str
    ) -> PolicyRevision:
        """Restore a prior posture by appending it as the new head.

        Parameters
        ----------
        digest : str
            The content address of the posture to restore; must already be in the
            history.
        author : str
            Who authorised the rollback.
        created_at : str
            When the rollback was recorded (ISO timestamp).
        reason : str
            Why the posture is being restored.

        Returns
        -------
        PolicyRevision
            The new head revision, whose digest equals ``digest``.

        Raises
        ------
        KeyError
            If ``digest`` is not present in the history.
        """
        target = self.get(digest)
        return self.record(
            target.profile, author=author, created_at=created_at, reason=reason
        )
