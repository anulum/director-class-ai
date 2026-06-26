# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — public claim-boundary guard

"""Reject public copy that outruns the current audit-chain evidence boundary."""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_SURFACES = (
    Path("README.md"),
    Path("CHANGELOG.md"),
    Path("docs"),
    Path("director_class_ai"),
    Path("demos"),
    Path("notebooks"),
)
_TEXT_SUFFIXES = {
    ".md",
    ".py",
    ".ipynb",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".rst",
    ".txt",
}
_IGNORED_NAMES = {"__pycache__"}
_IGNORED_PARTS = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv"}


@dataclass(frozen=True)
class ClaimBoundaryViolation:
    """A public-surface claim that exceeds the current evidence boundary.

    Parameters
    ----------
    path:
        Repository-relative file path containing the claim.
    line:
        One-based line number where the claim appears.
    phrase:
        Canonical overclaim phrase matched by the guard.
    reason:
        Operator-facing reason the claim is blocked.
    excerpt:
        Redacted line excerpt for diagnosis.
    """

    path: Path
    line: int
    phrase: str
    reason: str
    excerpt: str


@dataclass(frozen=True)
class _BlockedPattern:
    phrase: str
    pattern: re.Pattern[str]
    reason: str


_BLOCKED_PATTERNS = (
    _BlockedPattern(
        phrase="court-admissible",
        pattern=re.compile(r"\bcourt[-\s]?admissib(?:le|ility)\b", re.IGNORECASE),
        reason=(
            "legal admissibility requires external legal review and stronger "
            "chain anchoring than the current tamper-evident log provides"
        ),
    ),
    _BlockedPattern(
        phrase="proves its own integrity",
        pattern=re.compile(r"\bproves\s+its\s+own\s+integrity\b", re.IGNORECASE),
        reason=(
            "the current chain detects mutation only against the recorded head; "
            "it is not an independent integrity proof"
        ),
    ),
    _BlockedPattern(
        phrase="tamper-resistant",
        pattern=re.compile(r"\btamper[-\s]resistant\b", re.IGNORECASE),
        reason=(
            "tamper-resistant wording is blocked until signed or externally "
            "anchored heads exist"
        ),
    ),
    _BlockedPattern(
        phrase="tamper-proof",
        pattern=re.compile(r"\btamper[-\s]proof\b", re.IGNORECASE),
        reason="tamper-proof is stronger than the current tamper-evident record.",
    ),
    _BlockedPattern(
        phrase="legal evidence",
        pattern=re.compile(r"\blegal\s+evidence\b", re.IGNORECASE),
        reason=(
            "legal-evidence positioning is blocked until counsel-reviewed wording exists."
        ),
    ),
)


def validate_claim_boundaries(
    repo_root: Path = Path("."),
    surfaces: Sequence[Path] = _DEFAULT_SURFACES,
) -> list[ClaimBoundaryViolation]:
    """Return public claim-boundary violations for repository surfaces.

    Parameters
    ----------
    repo_root:
        Repository root used to resolve public documentation, demo, and package
        source paths.
    surfaces:
        Relative public surfaces to scan. Directories are walked recursively and
        missing paths are ignored so sparse documentation fixtures remain valid.

    Returns
    -------
    list[ClaimBoundaryViolation]
        Matched overclaims in deterministic path and line order.
    """
    root = repo_root.resolve()
    violations: list[ClaimBoundaryViolation] = []
    for path in _iter_public_surface_files(root, surfaces):
        relative = _relative(path, root)
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), 1
        ):
            for blocked in _BLOCKED_PATTERNS:
                if blocked.pattern.search(line):
                    violations.append(
                        ClaimBoundaryViolation(
                            path=relative,
                            line=line_number,
                            phrase=blocked.phrase,
                            reason=blocked.reason,
                            excerpt=" ".join(line.split())[:180],
                        )
                    )
    return violations


def main(argv: Sequence[str] | None = None) -> int:
    """Run the public claim-boundary guard from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument(
        "--surface",
        action="append",
        type=Path,
        dest="surfaces",
        help="Additional or replacement public surface path; may be repeated.",
    )
    args = parser.parse_args(argv)
    surfaces = tuple(args.surfaces) if args.surfaces else _DEFAULT_SURFACES
    violations = validate_claim_boundaries(args.repo_root, surfaces)
    for violation in violations:
        print(
            "claim boundary failed: "
            f"{violation.path}:{violation.line}: {violation.phrase}: "
            f"{violation.reason} -- {violation.excerpt}"
        )
    return 1 if violations else 0


def _iter_public_surface_files(root: Path, surfaces: Sequence[Path]) -> Iterable[Path]:
    for surface in surfaces:
        path = (root / surface).resolve()
        if path.is_file() and _is_scannable(path, root):
            yield path
        elif path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file() and _is_scannable(candidate, root):
                    yield candidate


def _is_scannable(path: Path, root: Path) -> bool:
    relative = _relative(path, root)
    if path.name in _IGNORED_NAMES:
        return False
    if any(part in _IGNORED_PARTS for part in relative.parts):
        return False
    if len(relative.parts) >= 2 and relative.parts[:2] == ("docs", "internal"):
        return False
    return path.suffix in _TEXT_SUFFIXES


def _relative(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


if __name__ == "__main__":
    raise SystemExit(main())
