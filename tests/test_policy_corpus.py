# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — exposure case corpus loader tests

from __future__ import annotations

import json
from pathlib import Path

from director_class_ai.core.signal import Locus, Plane, Severity
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
