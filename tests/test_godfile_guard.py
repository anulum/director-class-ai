# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — godfile guard tests

from __future__ import annotations

from pathlib import Path

from tools.check_godfiles import find_godfiles


def test_godfile_guard_accepts_small_file(tmp_path: Path) -> None:
    sample = tmp_path / "director_class_ai" / "small.py"
    sample.parent.mkdir()
    sample.write_text("x = 1\n", encoding="utf-8")

    assert find_godfiles([sample]) == []


def test_godfile_guard_rejects_oversized_production_file(tmp_path: Path) -> None:
    sample = tmp_path / "director_class_ai" / "huge.py"
    sample.parent.mkdir()
    sample.write_text("x = 1\n" * 1001, encoding="utf-8")

    failures = find_godfiles([sample])

    assert failures and "exceeds limit 1000" in failures[0]
