# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — test-quality guard tests

from __future__ import annotations

from pathlib import Path

from tools.check_test_quality import find_test_quality_failures


def test_quality_guard_accepts_real_surface_behaviour_test(tmp_path: Path) -> None:
    sample = tmp_path / "test_action_policy.py"
    sample.write_text(
        "\n".join(
            (
                "from director_class_ai.core import EvaluationRequest",
                "",
                "def test_request_keeps_action_text():",
                "    request = EvaluationRequest(action='ls')",
                "    assert request.action == 'ls'",
                "",
            )
        ),
        encoding="utf-8",
    )

    assert find_test_quality_failures([sample]) == []


def test_quality_guard_rejects_bucket_filename(tmp_path: Path) -> None:
    sample = tmp_path / "test_coverage_gap.py"
    sample.write_text(
        "from director_class_ai.core import EvaluationRequest\n"
        "def test_request():\n"
        "    assert EvaluationRequest(action='ls').action == 'ls'\n",
        encoding="utf-8",
    )

    failures = find_test_quality_failures([sample])

    assert failures and "forbidden coverage" in failures[0]


def test_quality_guard_rejects_import_only_file(tmp_path: Path) -> None:
    sample = tmp_path / "test_import_only.py"
    sample.write_text(
        "import director_class_ai\ndef test_imports():\n    director_class_ai\n",
        encoding="utf-8",
    )

    failures = find_test_quality_failures([sample])

    assert any("no behaviour assertion" in failure for failure in failures)
