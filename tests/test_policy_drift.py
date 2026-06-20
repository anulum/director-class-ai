# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy drift monitor tests

from __future__ import annotations

from director_class_ai.policy import (
    PolicyDriftEvent,
    PolicyDriftMonitor,
    PolicyRevision,
    Profile,
    profile_digest,
)


def _profile(**overrides: object) -> Profile:
    base: dict[str, object] = {"name": "staging", "action_block_threshold": 0.3}
    base.update(overrides)
    return Profile(**base)  # type: ignore[arg-type]


def _approved(profile: Profile | None = None) -> PolicyRevision:
    return PolicyRevision(
        profile=profile if profile is not None else _profile(),
        author="ops@anulum.li",
        created_at="2026-06-20T09:00:00Z",
        reason="approved baseline",
    )


class TestNoDrift:
    def test_matching_profile_returns_none_and_does_not_emit(self) -> None:
        emitted: list[PolicyDriftEvent] = []
        monitor = PolicyDriftMonitor(_approved(), sink=emitted.append)
        assert monitor.check(_profile(), detected_at="2026-06-20T10:00:00Z") is None
        assert emitted == []

    def test_approved_property_exposes_baseline(self) -> None:
        approved = _approved()
        assert PolicyDriftMonitor(approved).approved is approved


class TestDrift:
    def test_drift_emits_event_with_changes_and_digests(self) -> None:
        emitted: list[PolicyDriftEvent] = []
        approved = _approved(_profile(require_approval=True))
        monitor = PolicyDriftMonitor(approved, sink=emitted.append)

        live = _profile(require_approval=False)
        event = monitor.check(live, detected_at="2026-06-20T10:00:00Z")

        assert event is not None
        assert emitted == [event]
        assert event.approved_digest == approved.digest
        assert event.live_digest == profile_digest(live)
        assert event.detected_at == "2026-06-20T10:00:00Z"
        assert [change.field for change in event.changes] == ["require_approval"]
        assert event.changes[0].old is True
        assert event.changes[0].new is False

    def test_drift_without_sink_returns_event_and_emits_nothing(self) -> None:
        monitor = PolicyDriftMonitor(_approved(_profile(action_block_threshold=0.3)))
        event = monitor.check(
            _profile(action_block_threshold=0.9), detected_at="2026-06-20T10:00:00Z"
        )
        assert event is not None
        assert event.changes[0].field == "action_block_threshold"
