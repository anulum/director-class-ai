# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — boundary evidence guard tests

from __future__ import annotations

import json
from pathlib import Path

from tools.check_test_boundary_evidence import validate_boundary_evidence


def _write_ledger(root: Path, payload: dict[str, object]) -> Path:
    path = root / "ledger.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _valid_payload() -> dict[str, object]:
    return {
        "schema_version": "director-class-ai.test-boundary-evidence.v1",
        "boundaries": [
            {
                "id": "demo-boundary",
                "boundary_type": "cli",
                "production_surfaces": ["prod.py"],
                "required_behaviour": "CLI validates a real production path.",
                "evidence_tests": [
                    {
                        "file": "tests/test_demo_boundary.py",
                        "mode": "integration",
                        "covers": "real CLI path",
                    }
                ],
            }
        ],
    }


def test_boundary_evidence_accepts_complete_ledger(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "prod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "tests" / "test_demo_boundary.py").write_text(
        "def test_demo():\n    assert True\n",
        encoding="utf-8",
    )
    ledger = _write_ledger(tmp_path, _valid_payload())

    assert validate_boundary_evidence(tmp_path, ledger) == []


def test_boundary_evidence_rejects_missing_test_file(tmp_path: Path) -> None:
    (tmp_path / "prod.py").write_text("VALUE = 1\n", encoding="utf-8")
    ledger = _write_ledger(tmp_path, _valid_payload())

    failures = validate_boundary_evidence(tmp_path, ledger)

    assert any("missing test file" in failure for failure in failures)


def test_boundary_evidence_rejects_missing_production_surface(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_demo_boundary.py").write_text(
        "def test_demo():\n    assert True\n",
        encoding="utf-8",
    )
    ledger = _write_ledger(tmp_path, _valid_payload())

    failures = validate_boundary_evidence(tmp_path, ledger)

    assert any("missing referenced path" in failure for failure in failures)


def test_boundary_evidence_rejects_non_integration_mode(tmp_path: Path) -> None:
    payload = _valid_payload()
    boundary = payload["boundaries"][0]  # type: ignore[index]
    boundary["evidence_tests"][0]["mode"] = "unit"  # type: ignore[index]
    (tmp_path / "tests").mkdir()
    (tmp_path / "prod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "tests" / "test_demo_boundary.py").write_text(
        "def test_demo():\n    assert True\n",
        encoding="utf-8",
    )
    ledger = _write_ledger(tmp_path, payload)

    failures = validate_boundary_evidence(tmp_path, ledger)

    assert any("mode must be" in failure for failure in failures)
