# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — documentation surface guard

"""Validate public documentation, demo, and notebook entry points."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

_REQUIRED_FILES = (
    Path("README.md"),
    Path("docs/index.md"),
    Path("docs/onboarding.md"),
    Path("docs/demos.md"),
    Path("docs/evidence.md"),
    Path("docs/CLAIM_BOUNDARIES.md"),
    Path("demos/action_checkpoint.py"),
    Path("notebooks/action_checkpoint.ipynb"),
)
_REQUIRED_README_SECTIONS = (
    "## Action checkpoint in five lines",
    "## Python middleware",
    "## MCP gateway service",
    "## Command guard",
    "## External benchmark artefacts",
    "## Local verification",
)
_REQUIRED_COMMANDS = (
    "make preflight",
    "make bench-evidence",
    "python demos/action_checkpoint.py",
    "director-class-guard",
)
_CLAIM_BOUNDARY_PHRASES = (
    "not a public advantage claim",
    "not comparative benchmark claims",
    "not a comparative benchmark claim",
)


def validate_documentation_surface(repo_root: Path = Path(".")) -> list[str]:
    """Return documentation surface validation failures.

    Parameters
    ----------
    repo_root:
        Repository root used to resolve documentation paths.

    Returns
    -------
    list[str]
        Human-readable failures. An empty list means the documentation, demo,
        and notebook entry points are present and coherent.
    """
    root = repo_root.resolve()
    failures: list[str] = []
    for relative in _REQUIRED_FILES:
        if not (root / relative).is_file():
            failures.append(f"missing required documentation surface: {relative}")

    failures.extend(_validate_readme(root / "README.md"))
    failures.extend(_validate_docs(root))
    failures.extend(_validate_notebook(root / "notebooks/action_checkpoint.ipynb"))
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    """Run the documentation surface guard."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    failures = validate_documentation_surface(args.repo_root)
    for failure in failures:
        print(f"documentation surface failed: {failure}")
    return 1 if failures else 0


def _validate_readme(path: Path) -> list[str]:
    if not path.exists():
        return [f"{path}: missing"]
    text = path.read_text(encoding="utf-8")
    failures: list[str] = []
    for section in _REQUIRED_README_SECTIONS:
        if section not in text:
            failures.append(f"README missing section {section!r}")
    for command in _REQUIRED_COMMANDS:
        if command not in text:
            failures.append(f"README missing command/reference {command!r}")
    return failures


def _validate_docs(root: Path) -> list[str]:
    failures: list[str] = []
    docs_text = "\n".join(
        (root / path).read_text(encoding="utf-8")
        for path in (
            Path("docs/index.md"),
            Path("docs/onboarding.md"),
            Path("docs/demos.md"),
            Path("docs/evidence.md"),
        )
        if (root / path).exists()
    )
    for command in _REQUIRED_COMMANDS:
        if command not in docs_text:
            failures.append(f"docs surface missing command/reference {command!r}")
    normalised_docs = " ".join(docs_text.split())
    if not any(phrase in normalised_docs for phrase in _CLAIM_BOUNDARY_PHRASES):
        failures.append("docs surface missing benchmark claim boundary language")
    return failures


def _validate_notebook(path: Path) -> list[str]:
    if not path.exists():
        return [f"{path}: missing"]
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        return [f"{path}: notebook root must be an object"]
    cells = loaded.get("cells")
    failures: list[str] = []
    if not isinstance(cells, list) or len(cells) < 2:
        failures.append(f"{path}: notebook must contain markdown and code cells")
        cells = [] if not isinstance(cells, list) else cells
    source = "\n".join(_cell_source(cell) for cell in cells if isinstance(cell, dict))
    if "run_guard" not in source:
        failures.append(f"{path}: notebook must exercise run_guard")
    if "destructive_command" not in source:
        failures.append(f"{path}: notebook must assert destructive command firing")
    if "not a comparative benchmark claim" not in source:
        failures.append(f"{path}: notebook must state the benchmark claim boundary")
    return failures


def _cell_source(cell: Mapping[str, object]) -> str:
    source = cell.get("source", "")
    if isinstance(source, str):
        return source
    if isinstance(source, list):
        return "".join(item for item in source if isinstance(item, str))
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
