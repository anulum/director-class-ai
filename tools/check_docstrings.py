# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — public docstring guard

"""Fail when public production modules, classes, or callables lack docstrings."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path("director_class_ai")


def _is_public(name: str) -> bool:
    return not name.startswith("_")


def _missing(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    missing: list[str] = []
    if ast.get_docstring(tree) is None:
        missing.append(f"{path}:1: module")
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and _is_public(node.name):
            if ast.get_docstring(node) is None:
                missing.append(f"{path}:{node.lineno}: class {node.name}")
            for member in node.body:
                if (
                    isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef)
                    and _is_public(member.name)
                    and ast.get_docstring(member) is None
                ):
                    missing.append(
                        f"{path}:{member.lineno}: method {node.name}.{member.name}"
                    )
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _is_public(
            node.name
        ):
            if ast.get_docstring(node) is None:
                missing.append(f"{path}:{node.lineno}: function {node.name}")
    return missing


def main() -> int:
    """Check every production Python file for public docstring coverage."""
    failures: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        failures.extend(_missing(path))
    if failures:
        print("Missing public docstrings:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
