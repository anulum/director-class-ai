# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — content-addressed policy revisions

"""Content-addressed policy revisions, diffs, and drift detection.

Guardrail-as-Code, first increment. A deployment :class:`Profile` is the
governance posture for one environment; this module turns each posture into a
content-addressed revision so a change can be reviewed, a running profile can be
checked for drift against the approved posture before it governs live actions,
and a prior posture can be restored by walking the parent lineage.

The revision digest is the SHA-256 of the profile's canonical governance payload
(its fields only), serialised the same way as the tamper-evident audit chain
(``json.dumps(..., sort_keys=True, separators=(",", ":"))``). Two revisions with
identical policy content therefore share a digest regardless of who authored
them or when, so a rollback to a prior posture is detectable by digest equality;
the author, timestamp, reason, and parent digest record lineage without changing
the content address.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .profile import Profile

__all__ = [
    "PolicyFieldChange",
    "PolicyRevision",
    "diff_profiles",
    "profile_digest",
]


def _canonical_payload(profile: Profile) -> str:
    """Serialise a profile's governance fields to a canonical JSON string.

    Parameters
    ----------
    profile : Profile
        The deployment profile to serialise.

    Returns
    -------
    str
        The profile fields as JSON with sorted keys and no insignificant
        whitespace, matching the audit-chain serialisation.
    """
    payload = {name: getattr(profile, name) for name in Profile.field_names()}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def profile_digest(profile: Profile) -> str:
    """Return the SHA-256 content address of a profile's governance payload.

    Parameters
    ----------
    profile : Profile
        The deployment profile to address.

    Returns
    -------
    str
        The hex SHA-256 digest of the canonical payload.
    """
    return hashlib.sha256(_canonical_payload(profile).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PolicyFieldChange:
    """One governance field that differs between two profiles.

    Attributes
    ----------
    field : str
        The profile field name that changed.
    old, new : object
        The field value before and after the change.
    """

    field: str
    old: object
    new: object


def diff_profiles(old: Profile, new: Profile) -> tuple[PolicyFieldChange, ...]:
    """Return the governance fields that changed from ``old`` to ``new``.

    Parameters
    ----------
    old, new : Profile
        The profiles to compare.

    Returns
    -------
    tuple of PolicyFieldChange
        One entry per field whose value differs, ordered by field name; empty
        when the two postures are identical.
    """
    changes = [
        PolicyFieldChange(field=name, old=getattr(old, name), new=getattr(new, name))
        for name in sorted(Profile.field_names())
        if getattr(old, name) != getattr(new, name)
    ]
    return tuple(changes)


@dataclass(frozen=True)
class PolicyRevision:
    """A content-addressed, authored snapshot of one deployment profile.

    Attributes
    ----------
    profile : Profile
        The governance posture captured by this revision.
    author : str
        Who recorded the change; must be non-empty so no posture change is
        unattributed.
    created_at : str
        When the change was recorded (caller-supplied ISO timestamp, kept out of
        the content address).
    reason : str
        Why the change was made; must be non-empty so the audit trail explains
        every posture change.
    parent : str or None
        The digest of the revision this one supersedes, or ``None`` for the first
        revision in a lineage.
    """

    profile: Profile
    author: str
    created_at: str
    reason: str
    parent: str | None = None

    def __post_init__(self) -> None:
        """Reject revisions that omit attribution, timestamp, or reason."""
        if not self.author.strip():
            raise ValueError("a policy revision must record a non-empty author")
        if not self.created_at.strip():
            raise ValueError("a policy revision must record a created_at timestamp")
        if not self.reason.strip():
            raise ValueError("a policy revision must record a non-empty reason")

    @property
    def digest(self) -> str:
        """Return the SHA-256 content address of this revision's posture."""
        return profile_digest(self.profile)

    def diff(self, other: PolicyRevision) -> tuple[PolicyFieldChange, ...]:
        """Return the governance changes from this revision to ``other``.

        Parameters
        ----------
        other : PolicyRevision
            The revision to compare against.

        Returns
        -------
        tuple of PolicyFieldChange
            The fields that differ between the two revisions' profiles.
        """
        return diff_profiles(self.profile, other.profile)

    def drift(self, live: Profile) -> tuple[PolicyFieldChange, ...]:
        """Return how a live profile has drifted from this approved revision.

        Parameters
        ----------
        live : Profile
            The profile a deployment is currently running.

        Returns
        -------
        tuple of PolicyFieldChange
            The fields where the live posture differs from this approved one;
            empty when the live profile still matches the approved revision.
        """
        return diff_profiles(self.profile, live)

    def matches(self, live: Profile) -> bool:
        """Return whether a live profile is content-identical to this revision.

        Parameters
        ----------
        live : Profile
            The profile to check.

        Returns
        -------
        bool
            ``True`` when the live profile's content address equals this
            revision's digest.
        """
        return profile_digest(live) == self.digest

    def child(
        self, profile: Profile, *, author: str, created_at: str, reason: str
    ) -> PolicyRevision:
        """Return the next revision, linking this revision's digest as parent.

        Parameters
        ----------
        profile : Profile
            The new governance posture.
        author : str
            Who recorded the new revision.
        created_at : str
            When the new revision was recorded (ISO timestamp).
        reason : str
            Why the posture changed.

        Returns
        -------
        PolicyRevision
            A revision whose ``parent`` is this revision's digest.
        """
        return PolicyRevision(
            profile=profile,
            author=author,
            created_at=created_at,
            reason=reason,
            parent=self.digest,
        )
