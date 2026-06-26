# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — public claim-boundary guard tests

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tools.check_claim_boundaries import main, validate_claim_boundaries

_ROOT = Path(__file__).resolve().parent.parent


def test_claim_boundary_guard_accepts_current_public_surfaces() -> None:
    violations = validate_claim_boundaries(_ROOT)

    assert violations == []
    assert main(("--repo-root", str(_ROOT))) == 0


def test_claim_boundary_guard_rejects_admissibility_and_self_proof(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (tmp_path / "README.md").write_text(
        "The audit chain is court-admissible and proves its own integrity.\n",
        encoding="utf-8",
    )
    (docs / "sales.md").write_text(
        "This tamper-resistant record is ready for legal evidence.\n",
        encoding="utf-8",
    )

    violations = validate_claim_boundaries(tmp_path)

    assert [violation.phrase for violation in violations] == [
        "court-admissible",
        "proves its own integrity",
        "tamper-resistant",
        "legal evidence",
    ]


def test_claim_boundary_cli_reports_file_and_line(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "Director-Class AI emits tamper-proof audit records.\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "tools" / "check_claim_boundaries.py"),
            "--repo-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "README.md:1" in completed.stdout
    assert "tamper-proof" in completed.stdout
