# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — A/B posture exposure tests

from __future__ import annotations

from director_class_ai.core.signal import DetectorSignal, Locus, Plane, Severity
from director_class_ai.policy import (
    ExposureCase,
    PostureExposure,
    Profile,
)


def _action(score: float) -> tuple[DetectorSignal, ...]:
    return (
        DetectorSignal(
            detector="d",
            plane=Plane.ACTION,
            score=score,
            locus=Locus.ACTION,
            signal_type="destructive_command",
            severity=Severity.HIGH,
        ),
    )


def _baseline() -> Profile:
    return Profile(name="staging", action_block_threshold=0.3, uncertainty_margin=0.0)


def _candidate() -> Profile:
    return Profile(name="staging", action_block_threshold=0.7, uncertainty_margin=0.0)


_CASES = [
    ExposureCase(label="safe", signals=_action(0.1)),
    ExposureCase(label="mid", signals=_action(0.5)),
    ExposureCase(label="authorised", signals=_action(0.5), provenance="user"),
    ExposureCase(label="danger", signals=_action(0.9)),
]


class TestPostureExposure:
    def test_each_case_is_classified_under_both_postures(self) -> None:
        report = PostureExposure(_baseline(), _candidate()).expose(_CASES)
        by_label = {o.label: (o.baseline, o.candidate) for o in report.outcomes}
        assert by_label == {
            "safe": ("allow", "allow"),
            "mid": ("block", "allow"),
            "authorised": ("escalate", "allow"),
            "danger": ("block", "block"),
        }

    def test_changed_subset_and_count(self) -> None:
        report = PostureExposure(_baseline(), _candidate()).expose(_CASES)
        assert [o.label for o in report.changed] == ["mid", "authorised"]
        assert report.changed_count == 2

    def test_transition_counts(self) -> None:
        report = PostureExposure(_baseline(), _candidate()).expose(_CASES)
        assert report.transitions == {"block->allow": 1, "escalate->allow": 1}

    def test_outcome_change_helpers(self) -> None:
        report = PostureExposure(_baseline(), _candidate()).expose(_CASES)
        mid = next(o for o in report.outcomes if o.label == "mid")
        safe = next(o for o in report.outcomes if o.label == "safe")
        assert mid.changed is True
        assert mid.transition == "block->allow"
        assert safe.changed is False
        assert safe.transition == "allow->allow"

    def test_identical_postures_report_no_change(self) -> None:
        report = PostureExposure(_baseline(), _baseline()).expose(_CASES)
        assert report.changed_count == 0
        assert report.transitions == {}

    def test_empty_case_set(self) -> None:
        report = PostureExposure(_baseline(), _candidate()).expose([])
        assert report.outcomes == ()
        assert report.changed_count == 0
        assert report.transitions == {}
