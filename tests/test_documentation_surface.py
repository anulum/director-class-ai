# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — documentation surface tests

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from tools.check_documentation_surface import main, validate_documentation_surface

_ROOT = Path(__file__).resolve().parent.parent


def _copy_docs_surface(tmp_path: Path) -> Path:
    for relative in (
        "README.md",
        "docs/index.md",
        "docs/onboarding.md",
        "docs/demos.md",
        "docs/evidence.md",
        "docs/CLAIM_BOUNDARIES.md",
        "demos/action_checkpoint.py",
        "notebooks/action_checkpoint.ipynb",
    ):
        source = _ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return tmp_path


def test_documentation_surface_accepts_current_docs(tmp_path: Path) -> None:
    repo = _copy_docs_surface(tmp_path)

    assert validate_documentation_surface(repo) == []
    assert main(("--repo-root", str(repo))) == 0


def test_documentation_surface_rejects_missing_onboarding(tmp_path: Path) -> None:
    repo = _copy_docs_surface(tmp_path)
    (repo / "docs/onboarding.md").unlink()

    failures = validate_documentation_surface(repo)

    assert any("docs/onboarding.md" in failure for failure in failures)


def test_documentation_surface_rejects_notebook_without_demo_code(
    tmp_path: Path,
) -> None:
    repo = _copy_docs_surface(tmp_path)
    notebook_path = repo / "notebooks/action_checkpoint.ipynb"
    notebook = json.loads(notebook_path.read_text(encoding="utf-8"))
    notebook["cells"] = notebook["cells"][:1]
    notebook_path.write_text(json.dumps(notebook), encoding="utf-8")

    failures = validate_documentation_surface(repo)

    assert any("run_guard" in failure for failure in failures)


def test_action_checkpoint_demo_runs_and_redacts_command_text() -> None:
    completed = subprocess.run(
        [sys.executable, "demos/action_checkpoint.py"],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    events = json.loads(completed.stdout)

    assert events[0]["route"] == "allow"
    assert events[0]["executed"] is False
    assert events[1]["executed"] is False
    assert "destructive_command" in events[1]["firing"]
    assert "rm -rf" not in completed.stdout
