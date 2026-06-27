# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — SPDX header guard

"""Fail if any tracked Python source lacks the SPDX licence header.

Run in pre-commit and CI so every file declares its licence (REUSE-style),
matching the GOTM repo standard.
"""

from __future__ import annotations

import sys
from pathlib import Path

_TAG = "SPDX-License-Identifier: BUSL-1.1"
_ROOTS = ("director_class_ai", "tests", "benchmarks", "tools", "demos")


def offenders(repo_root: Path) -> list[Path]:
    """Return tracked Python files that lack the BUSL SPDX header.

    Parameters
    ----------
    repo_root
        Repository root containing the configured source roots.

    Returns
    -------
    list of Path
        Python files whose header window does not contain the required SPDX tag.
    """
    bad: list[Path] = []
    for root in _ROOTS:
        for path in (repo_root / root).rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            head = path.read_text(encoding="utf-8")[:400]
            if _TAG not in head:
                bad.append(path)
    return bad


def main() -> int:
    """Run the SPDX header scan for this repository checkout.

    Returns
    -------
    int
        ``0`` when all checked files contain the required tag, otherwise ``1``.
    """
    bad = offenders(Path(__file__).resolve().parent.parent)
    for path in bad:
        print(f"missing SPDX header: {path}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
