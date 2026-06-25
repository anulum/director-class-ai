# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — godfile guard

"""Fail when Python files grow past the repo's responsibility-size limits."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

_LIMITS = {
    "director_class_ai": 1_000,
    "benchmarks": 800,
    "tests": 800,
    "tools": 500,
    "demos": 500,
}
_DEFAULT_ROOTS = tuple(Path(name) for name in _LIMITS)


def _line_count(path: Path) -> int:
    return len(path.read_text(encoding="utf-8").splitlines())


def _limit_for(path: Path) -> int | None:
    for part in path.parts:
        if part in _LIMITS:
            return _LIMITS[part]
    return None


def find_godfiles(paths: Iterable[Path]) -> list[str]:
    """Return files that exceed their configured size limit."""
    failures: list[str] = []
    for path in sorted({p for p in paths if p.is_file() and p.suffix == ".py"}):
        limit = _limit_for(path)
        if limit is None:
            continue
        count = _line_count(path)
        if count > limit:
            failures.append(f"{path}: {count} lines exceeds limit {limit}")
    return failures


def _iter_python_files(roots: Sequence[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(root.rglob("*.py"))
    return files


def main(argv: Sequence[str] | None = None) -> int:
    """Run the godfile guard."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args(argv)
    roots = tuple(args.paths) if args.paths else _DEFAULT_ROOTS
    failures = find_godfiles(_iter_python_files(roots))
    for failure in failures:
        print(f"godfile guard failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
