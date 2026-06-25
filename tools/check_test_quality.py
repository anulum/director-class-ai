# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — test-quality guard

"""Fail on coverage-bucket names and import-only test files."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

_FORBIDDEN_NAME = re.compile(
    r"(^test_(?:cov|coverage)|coverage_closure|final_gap|remaining|"
    r"bucket|misc|new_module|push)",
    re.IGNORECASE,
)
_REAL_SURFACE_IMPORTS = ("director_class_ai", "benchmarks", "tools", "demos")
_ASSERTING_NODES = (
    ast.Assert,
    ast.Raise,
    ast.With,
    ast.Try,
    ast.For,
    ast.AsyncFor,
    ast.While,
)


def _test_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    ]


def _imports_real_surface(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported = (alias.name.split(".")[0] for alias in node.names)
            if any(name in _REAL_SURFACE_IMPORTS for name in imported):
                return True
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in _REAL_SURFACE_IMPORTS:
                return True
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in _REAL_SURFACE_IMPORTS:
                return True
    return False


def _has_behavior_assertion(
    functions: Sequence[ast.FunctionDef | ast.AsyncFunctionDef],
) -> bool:
    for function in functions:
        for node in ast.walk(function):
            if isinstance(node, _ASSERTING_NODES):
                return True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {
                    "raises",
                    "approx",
                    "match",
                    "exists",
                    "is_file",
                    "is_dir",
                    "read_text",
                    "write_text",
                }
            ):
                return True
    return False


def find_test_quality_failures(paths: Iterable[Path]) -> list[str]:
    """Return test files that violate static quality rules."""
    failures: list[str] = []
    for path in sorted({p for p in paths if p.is_file() and p.name.startswith("test_")}):
        if _FORBIDDEN_NAME.search(path.name):
            failures.append(f"{path}: forbidden coverage/bucket-style test filename")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            failures.append(f"{path}: cannot parse test file: {exc}")
            continue
        functions = _test_functions(tree)
        if not functions:
            failures.append(f"{path}: no test_* functions")
        if not _imports_real_surface(tree):
            failures.append(f"{path}: does not import a production repo surface")
        if functions and not _has_behavior_assertion(functions):
            failures.append(f"{path}: no behaviour assertion or failure path detected")
    return failures


def _iter_tests(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return list(root.rglob("test_*.py")) if root.is_dir() else []


def main(argv: Sequence[str] | None = None) -> int:
    """Run the test-quality guard."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args(argv)
    roots = tuple(args.paths) if args.paths else (Path("tests"),)
    files: list[Path] = []
    for root in roots:
        files.extend(_iter_tests(root))
    failures = find_test_quality_failures(files)
    for failure in failures:
        print(f"test quality failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
