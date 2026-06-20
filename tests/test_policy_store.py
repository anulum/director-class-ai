# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — durable governance state tests

from __future__ import annotations

import json
from pathlib import Path

import pytest

from director_class_ai.policy.history import PolicyHistory
from director_class_ai.policy.profile import Profile
from director_class_ai.policy.review import PolicyChangeProposal
from director_class_ai.policy.revision import PolicyRevision
from director_class_ai.policy.store import (
    GOVERNANCE_VERSION,
    deserialise_profile,
    deserialise_proposal,
    deserialise_revision,
    load_governance,
    save_governance,
    serialise_profile,
    serialise_proposal,
    serialise_revision,
)


def _profile(threshold: float = 0.3) -> Profile:
    return Profile(name="staging", action_block_threshold=threshold)


def _revision(parent: str | None = None, threshold: float = 0.3) -> PolicyRevision:
    return PolicyRevision(
        profile=_profile(threshold),
        author="alice",
        created_at="2026-06-20T10:00",
        reason="baseline",
        parent=parent,
    )


def test_profile_roundtrip() -> None:
    profile = _profile()
    restored = deserialise_profile(serialise_profile(profile))
    assert restored == profile


def test_revision_roundtrip_preserves_lineage_and_metadata() -> None:
    revision = _revision()
    child = revision.child(_profile(0.7), author="alice", created_at="t", reason="relax")
    restored = deserialise_revision(serialise_revision(child))
    assert restored == child
    assert restored.parent == revision.digest


def test_proposal_roundtrip_preserves_review_outcome() -> None:
    proposal = PolicyChangeProposal(
        revision=_revision(), status="approved", reviewer="bob", decided_at="t2"
    )
    restored = deserialise_proposal(serialise_proposal(proposal))
    assert restored == proposal


def test_save_and_load_governance_roundtrip(tmp_path: Path) -> None:
    history = PolicyHistory()
    base = history.record(_profile(), author="alice", created_at="t", reason="baseline")
    history.record(_profile(0.7), author="alice", created_at="t1", reason="relax")
    proposals = (
        PolicyChangeProposal(
            revision=_revision(threshold=0.4),
        ),
    )
    store = tmp_path / "gov.json"

    save_governance(store, history=history, proposals=proposals)
    loaded_history, loaded_proposals = load_governance(store)

    assert [r.digest for r in loaded_history.revisions] == [
        r.digest for r in history.revisions
    ]
    assert loaded_history.revisions[0].digest == base.digest
    assert loaded_proposals[0].digest == proposals[0].digest


def test_load_rejects_unsupported_version(tmp_path: Path) -> None:
    store = tmp_path / "gov.json"
    store.write_text(
        json.dumps({"version": 999, "history": [], "proposals": []}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unsupported governance store version"):
        load_governance(store)


def test_load_rejects_tampered_lineage(tmp_path: Path) -> None:
    store = tmp_path / "gov.json"
    forged = serialise_revision(_revision(parent="deadbeef"))
    store.write_text(
        json.dumps({"version": GOVERNANCE_VERSION, "history": [forged], "proposals": []}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must not declare a parent"):
        load_governance(store)
