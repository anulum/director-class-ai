# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — crash-durable file write tests

from __future__ import annotations

import os
from pathlib import Path

import pytest

from director_class_ai.core.durability import (
    _fsync_dir,
    atomic_write_text,
    durable_append_line,
)


def test_atomic_write_creates_file_with_content(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    atomic_write_text(target, '{"k": 1}')
    assert target.read_text(encoding="utf-8") == '{"k": 1}'


def test_atomic_write_overwrites_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    atomic_write_text(target, "old")
    atomic_write_text(target, "new")
    assert target.read_text(encoding="utf-8") == "new"
    assert list(tmp_path.iterdir()) == [target]  # the .tmp sibling was renamed away


def test_durable_append_accumulates_lines(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    durable_append_line(log, "a\n")
    durable_append_line(log, "b\n")
    assert log.read_text(encoding="utf-8") == "a\nb\n"


def test_fsync_dir_is_silent_for_a_valid_directory(tmp_path: Path) -> None:
    _fsync_dir(tmp_path)  # must not raise


def test_fsync_dir_ignores_a_missing_directory(tmp_path: Path) -> None:
    _fsync_dir(tmp_path / "does-not-exist")  # os.open raises OSError -> returns


def test_fsync_dir_tolerates_an_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(_fd: int) -> None:
        raise OSError("fsync unsupported")

    monkeypatch.setattr(os, "fsync", _raise)
    _fsync_dir(tmp_path)  # the inner OSError is swallowed, fd still closed
