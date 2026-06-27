# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — exposure case corpus loader tests

from __future__ import annotations

import json
from pathlib import Path

from director_class_ai.core.signal import Locus, Plane, Severity
from director_class_ai.policy import BlastRadius
from director_class_ai.policy.corpus import (
    case_from_mapping,
    load_cases,
    signal_from_mapping,
)


def test_signal_from_mapping_resolves_enums() -> None:
    signal = signal_from_mapping(
        {
            "detector": "shell_guard",
            "plane": "action",
            "score": 0.5,
            "locus": "action",
            "signal_type": "destructive_command",
            "severity": "high",
        }
    )
    assert signal.plane is Plane.ACTION
    assert signal.locus is Locus.ACTION
    assert signal.severity is Severity.HIGH
    assert signal.score == 0.5


def test_signal_from_mapping_defaults_severity_to_medium() -> None:
    signal = signal_from_mapping(
        {
            "detector": "d",
            "plane": "content",
            "score": 0.1,
            "locus": "claim",
            "signal_type": "contradiction",
        }
    )
    assert signal.severity is Severity.MEDIUM


def test_case_from_mapping_with_provenance() -> None:
    case = case_from_mapping(
        {
            "label": "row-1",
            "provenance": "user",
            "signals": [
                {
                    "detector": "d",
                    "plane": "action",
                    "score": 0.4,
                    "locus": "action",
                    "signal_type": "x",
                }
            ],
        }
    )
    assert case.label == "row-1"
    assert case.provenance == "user"
    assert len(case.signals) == 1


def test_case_from_mapping_with_capability_context_and_grants() -> None:
    case = case_from_mapping(
        {
            "label": "workspace-read",
            "provenance": "user",
            "signals": [],
            "capability_context": {
                "subject": "agent-a",
                "tenant": "tenant-a",
                "session": "session-a",
                "source_origin": "user",
                "tool": "fs/read_file",
                "resource": "workspace:README.md",
                "action": "read",
                "blast_radius": "low",
                "now": 10,
            },
            "capability_grants": [
                {
                    "grant_id": "read-workspace",
                    "subject": "agent-a",
                    "tenant": "tenant-a",
                    "session": "session-a",
                    "source_origin": "user",
                    "tool": "fs/read_file",
                    "resource": "workspace:README.md",
                    "action": "read",
                    "max_blast_radius": "low",
                    "expires_at": 20,
                }
            ],
        }
    )

    assert case.capability_context["resource"] == "workspace:README.md"
    assert len(case.capability_grants) == 1
    assert case.capability_grants[0].grant_id == "read-workspace"
    assert case.capability_grants[0].max_blast_radius.name == "LOW"


def test_case_from_mapping_accepts_numeric_blast_radius() -> None:
    case = case_from_mapping(
        {
            "label": "workspace-read",
            "signals": [],
            "capability_grants": [
                {
                    "grant_id": "read-workspace",
                    "subject": "agent-a",
                    "tenant": "tenant-a",
                    "session": "session-a",
                    "source_origin": "user",
                    "tool": "fs/read_file",
                    "resource": "workspace:README.md",
                    "action": "read",
                    "max_blast_radius": 1,
                }
            ],
        }
    )

    assert case.capability_grants[0].max_blast_radius is BlastRadius.LOW


def test_case_from_mapping_accepts_blast_radius_enum() -> None:
    case = case_from_mapping(
        {
            "label": "workspace-read",
            "signals": [],
            "capability_grants": [
                {
                    "grant_id": "read-workspace",
                    "subject": "agent-a",
                    "tenant": "tenant-a",
                    "session": "session-a",
                    "source_origin": "user",
                    "tool": "fs/read_file",
                    "resource": "workspace:README.md",
                    "action": "read",
                    "max_blast_radius": BlastRadius.LOW,
                }
            ],
        }
    )

    assert case.capability_grants[0].max_blast_radius is BlastRadius.LOW


def test_case_from_mapping_defaults_provenance_empty() -> None:
    case = case_from_mapping({"label": "row-2", "signals": []})
    assert case.provenance == ""
    assert case.signals == ()


def test_load_cases_reads_corpus(tmp_path: Path) -> None:
    corpus = tmp_path / "cases.json"
    corpus.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "label": "a",
                        "signals": [
                            {
                                "detector": "d",
                                "plane": "action",
                                "score": 0.9,
                                "locus": "action",
                                "signal_type": "destructive_command",
                            }
                        ],
                    },
                    {"label": "b", "signals": []},
                ]
            }
        ),
        encoding="utf-8",
    )
    cases = load_cases(corpus)
    assert [c.label for c in cases] == ["a", "b"]
    assert cases[0].signals[0].plane is Plane.ACTION
