# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — durable governance state

"""Serialise the policy governance state to JSON and back.

The operator workflow spans separate invocations — a posture is proposed in one
command and approved in another — so the revision lineage and its proposals must
outlive a single process. This module is the durable form: it serialises a
:class:`~director_class_ai.policy.history.PolicyHistory` and its
:class:`~director_class_ai.policy.review.PolicyChangeProposal` set to a JSON file
and rebuilds them on load.

On load the history is reconstructed by replaying :meth:`PolicyHistory.append`,
so a tampered file whose lineage no longer chains (a forged parent, a reordered
revision) is rejected exactly as an in-memory fork would be — the durable form
cannot smuggle in a posture that never passed lineage integrity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .history import PolicyHistory
from .loader import load_profile
from .profile import Profile
from .review import PolicyChangeProposal
from .revision import PolicyRevision

__all__ = [
    "GOVERNANCE_VERSION",
    "deserialise_profile",
    "deserialise_proposal",
    "deserialise_revision",
    "load_governance",
    "save_governance",
    "serialise_profile",
    "serialise_proposal",
    "serialise_revision",
]

GOVERNANCE_VERSION = 1


def serialise_profile(profile: Profile) -> dict[str, Any]:
    """Return a profile as a JSON-ready dict of its governance fields."""
    return {name: getattr(profile, name) for name in Profile.field_names()}


def deserialise_profile(data: dict[str, Any]) -> Profile:
    """Rebuild and revalidate a profile from its serialised fields."""
    return load_profile(dict(data))


def serialise_revision(revision: PolicyRevision) -> dict[str, Any]:
    """Return a revision (posture plus lineage metadata) as a JSON-ready dict."""
    return {
        "profile": serialise_profile(revision.profile),
        "author": revision.author,
        "created_at": revision.created_at,
        "reason": revision.reason,
        "parent": revision.parent,
    }


def deserialise_revision(data: dict[str, Any]) -> PolicyRevision:
    """Rebuild a revision from its serialised posture and lineage metadata."""
    return PolicyRevision(
        profile=deserialise_profile(data["profile"]),
        author=data["author"],
        created_at=data["created_at"],
        reason=data["reason"],
        parent=data["parent"],
    )


def serialise_proposal(proposal: PolicyChangeProposal) -> dict[str, Any]:
    """Return a proposal (revision plus review outcome) as a JSON-ready dict."""
    return {
        "revision": serialise_revision(proposal.revision),
        "status": proposal.status,
        "reviewer": proposal.reviewer,
        "decided_at": proposal.decided_at,
    }


def deserialise_proposal(data: dict[str, Any]) -> PolicyChangeProposal:
    """Rebuild a proposal from its serialised revision and review outcome."""
    return PolicyChangeProposal(
        revision=deserialise_revision(data["revision"]),
        status=data["status"],
        reviewer=data["reviewer"],
        decided_at=data["decided_at"],
    )


def save_governance(
    path: str | Path,
    *,
    history: PolicyHistory,
    proposals: tuple[PolicyChangeProposal, ...],
) -> None:
    """Write the revision lineage and its proposals to ``path`` as JSON.

    Parameters
    ----------
    path : str or Path
        Destination file; overwritten if it exists.
    history : PolicyHistory
        The revision lineage to persist.
    proposals : tuple of PolicyChangeProposal
        Every proposal — pending and terminal — to persist.
    """
    payload = {
        "version": GOVERNANCE_VERSION,
        "history": [serialise_revision(r) for r in history.revisions],
        "proposals": [serialise_proposal(p) for p in proposals],
    }
    with Path(path).open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def load_governance(
    path: str | Path,
) -> tuple[PolicyHistory, tuple[PolicyChangeProposal, ...]]:
    """Read and rebuild the revision lineage and its proposals from ``path``.

    Parameters
    ----------
    path : str or Path
        The governance JSON file to read.

    Returns
    -------
    tuple of (PolicyHistory, tuple of PolicyChangeProposal)
        The reconstructed lineage and proposals.

    Raises
    ------
    ValueError
        If the file declares an unsupported version, or its history does not
        chain (a forged parent or reordered revision fails lineage integrity).
    """
    with Path(path).open("rb") as fh:
        payload: dict[str, Any] = json.load(fh)
    version = payload.get("version")
    if version != GOVERNANCE_VERSION:
        raise ValueError(
            f"unsupported governance store version {version!r}, "
            f"expected {GOVERNANCE_VERSION}"
        )
    history = PolicyHistory()
    for revision_data in payload["history"]:
        history.append(deserialise_revision(revision_data))
    proposals = tuple(
        deserialise_proposal(proposal_data) for proposal_data in payload["proposals"]
    )
    return history, proposals
