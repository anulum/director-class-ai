# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — repository readiness tests

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.check_repository_readiness import main, validate_repository_readiness

_ROOT = Path(__file__).resolve().parent.parent


def _copy_readiness_surface(tmp_path: Path) -> Path:
    for path in (
        "pyproject.toml",
        "LICENSE",
        "Makefile",
        "validation/repository_readiness.json",
        ".github/workflows/ci.yml",
        ".github/workflows/pre-commit.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/scorecard.yml",
    ):
        source = _ROOT / path
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return tmp_path


def test_repository_readiness_accepts_current_surface(tmp_path: Path) -> None:
    repo = _copy_readiness_surface(tmp_path)

    assert validate_repository_readiness(repo) == []
    assert main(("--repo-root", str(repo))) == 0


def test_repository_readiness_rejects_missing_private_classifier(
    tmp_path: Path,
) -> None:
    repo = _copy_readiness_surface(tmp_path)
    pyproject = repo / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            '    "Private :: Do Not Upload",\n',
            "",
        ),
        encoding="utf-8",
    )

    failures = validate_repository_readiness(repo)

    assert any("Private :: Do Not Upload" in failure for failure in failures)


def test_repository_readiness_rejects_missing_remote_blockers(
    tmp_path: Path,
) -> None:
    repo = _copy_readiness_surface(tmp_path)
    spec_path = repo / "validation/repository_readiness.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    spec["open_remote_blockers"] = []
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")

    failures = validate_repository_readiness(repo)

    assert any("open_remote_blockers" in failure for failure in failures)


def test_repository_readiness_accepts_completed_remote_evidence(
    tmp_path: Path,
) -> None:
    repo = _copy_readiness_surface(tmp_path)
    spec_path = repo / "validation/repository_readiness.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    spec["remote_ci_status"] = "green_on_main"
    spec["branch_protection_status"] = "required_checks_configured"
    spec["open_remote_blockers"] = [
        "Historical filter-repo rewriting is not performed from this working "
        "checkout without explicit approval because it changes repository history."
    ]
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")

    assert validate_repository_readiness(repo) == []


def test_repository_readiness_rejects_unknown_remote_status(
    tmp_path: Path,
) -> None:
    repo = _copy_readiness_surface(tmp_path)
    spec_path = repo / "validation/repository_readiness.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    spec["remote_ci_status"] = "green-ish"
    spec["branch_protection_status"] = "maybe"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")

    failures = validate_repository_readiness(repo)

    assert any("remote_ci_status" in failure for failure in failures)
    assert any("branch_protection_status" in failure for failure in failures)


def test_repository_readiness_rejects_missing_ci_job(tmp_path: Path) -> None:
    repo = _copy_readiness_surface(tmp_path)
    ci = repo / ".github/workflows/ci.yml"
    ci.write_text(
        ci.read_text(encoding="utf-8").replace("name: Build & Wheel Smoke", ""),
        encoding="utf-8",
    )

    failures = validate_repository_readiness(repo)

    assert any("Build & Wheel Smoke" in failure for failure in failures)


def test_repository_readiness_rejects_missing_all_python_types_gate(
    tmp_path: Path,
) -> None:
    repo = _copy_readiness_surface(tmp_path)
    makefile = repo / "Makefile"
    makefile.write_text(
        makefile.read_text(encoding="utf-8").replace("types-all", "types-broad"),
        encoding="utf-8",
    )

    failures = validate_repository_readiness(repo)

    assert any("types-all" in failure for failure in failures)


def test_repository_readiness_rejects_lower_than_full_coverage_gate(
    tmp_path: Path,
) -> None:
    repo = _copy_readiness_surface(tmp_path)
    pyproject = repo / "pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8")
        .replace(
            "--cov-fail-under=100",
            "--cov-fail-under=97",
        )
        .replace(
            "fail_under = 100",
            "fail_under = 97",
        ),
        encoding="utf-8",
    )

    failures = validate_repository_readiness(repo)

    assert any("coverage gate" in failure for failure in failures)
