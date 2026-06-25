# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — boundary test evidence guard

"""Validate the boundary-crossing integration/e2e test evidence ledger."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

_DEFAULT_LEDGER = Path("validation/test_boundary_evidence.json")
_SCHEMA = "director-class-ai.test-boundary-evidence.v1"
_EVIDENCE_MODES = frozenset({"integration", "e2e"})


def validate_boundary_evidence(
    repo_root: Path = Path("."),
    ledger_path: Path = _DEFAULT_LEDGER,
) -> list[str]:
    """Return boundary-evidence validation failures."""
    root = repo_root.resolve()
    ledger_file = ledger_path if ledger_path.is_absolute() else root / ledger_path
    try:
        payload = json.loads(ledger_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return [f"{ledger_file}: cannot load boundary evidence: {exc}"]
    if not isinstance(payload, dict):
        return [f"{ledger_file}: top-level value must be an object"]

    failures: list[str] = []
    if payload.get("schema_version") != _SCHEMA:
        failures.append(f"schema_version must be {_SCHEMA!r}")

    boundaries = payload.get("boundaries")
    if not isinstance(boundaries, list) or not boundaries:
        return [*failures, "boundaries must be a non-empty list"]

    seen_ids: set[str] = set()
    for index, item in enumerate(boundaries):
        if not isinstance(item, dict):
            failures.append(f"boundaries[{index}] must be an object")
            continue
        boundary_id = _required_text(item, "id", failures, f"boundaries[{index}]")
        if boundary_id:
            if boundary_id in seen_ids:
                failures.append(f"duplicate boundary id {boundary_id!r}")
            seen_ids.add(boundary_id)
        _required_text(
            item,
            "boundary_type",
            failures,
            boundary_id or f"boundaries[{index}]",
        )
        _required_text(
            item,
            "required_behaviour",
            failures,
            boundary_id or f"boundaries[{index}]",
        )
        _validate_paths(
            root,
            item,
            "production_surfaces",
            failures,
            boundary_id or f"boundaries[{index}]",
        )
        _validate_evidence_tests(
            root,
            item,
            failures,
            boundary_id or f"boundaries[{index}]",
        )
    return failures


def _required_text(
    item: Mapping[str, object],
    key: str,
    failures: list[str],
    label: str,
) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        failures.append(f"{label}: {key} must be a non-empty string")
        return ""
    return value.strip()


def _validate_paths(
    root: Path,
    item: Mapping[str, object],
    key: str,
    failures: list[str],
    label: str,
) -> None:
    values = item.get(key)
    if not isinstance(values, list) or not values:
        failures.append(f"{label}: {key} must be a non-empty list")
        return
    for value in values:
        if not isinstance(value, str) or not value.strip():
            failures.append(f"{label}: {key} contains a non-string path")
            continue
        if not (root / value).exists():
            failures.append(f"{label}: missing referenced path {value!r}")


def _validate_evidence_tests(
    root: Path,
    item: Mapping[str, object],
    failures: list[str],
    label: str,
) -> None:
    tests = item.get("evidence_tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{label}: evidence_tests must be a non-empty list")
        return
    for index, evidence in enumerate(tests):
        prefix = f"{label}: evidence_tests[{index}]"
        if not isinstance(evidence, dict):
            failures.append(f"{prefix} must be an object")
            continue
        test_file = _required_text(evidence, "file", failures, prefix)
        mode = _required_text(evidence, "mode", failures, prefix)
        _required_text(evidence, "covers", failures, prefix)
        if mode and mode not in _EVIDENCE_MODES:
            failures.append(f"{prefix}: mode must be one of {sorted(_EVIDENCE_MODES)!r}")
        if test_file:
            path = root / test_file
            if not path.exists():
                failures.append(f"{prefix}: missing test file {test_file!r}")
            elif not path.name.startswith("test_") or path.suffix != ".py":
                failures.append(f"{prefix}: evidence file must be a pytest test file")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the boundary evidence guard."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--ledger", type=Path, default=_DEFAULT_LEDGER)
    args = parser.parse_args(argv)
    failures = validate_boundary_evidence(args.repo_root, args.ledger)
    for failure in failures:
        print(f"boundary evidence failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
