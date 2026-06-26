# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — Phase 4 task intake guard

"""Validate the internal Phase 4 task-intake ledger.

Phase 4 work is allowed to start only after the task declares its buyer/user
value, threat model, evidence requirement, affected surfaces, benchmark impact,
and claim boundary. This guard keeps that rule executable instead of leaving it
as an unchecked planning sentence.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

_DEFAULT_INTAKE = Path("validation/phase4_task_intake.json")
_SCHEMA_VERSION = "director-class-ai.phase4-task-intake.v1"
_STATUSES = frozenset({"ready", "in_progress", "done", "blocked", "deferred"})
_BENCHMARK_IMPACTS = frozenset(
    {"none", "functional_regression", "isolated_required", "external_required"}
)
_READY_STATES = frozenset({"ready", "executed"})
_REQUIRED_STRING_FIELDS = (
    "id",
    "plan_anchor",
    "status",
    "buyer_user_value",
    "threat_model",
    "benchmark_impact",
    "claim_boundary",
    "implementation_readiness",
)
_REQUIRED_LIST_FIELDS = ("required_evidence", "affected_surfaces")


@dataclass(frozen=True)
class Phase4TaskIntake:
    """One Phase 4 task-intake record loaded from the internal ledger."""

    task_id: str
    status: str
    plan_anchor: str
    buyer_user_value: str
    threat_model: str
    required_evidence: tuple[str, ...]
    affected_surfaces: tuple[str, ...]
    benchmark_impact: str
    claim_boundary: str
    implementation_readiness: str
    open_blockers: tuple[str, ...]

    @classmethod
    def from_mapping(cls, row: Mapping[str, object], index: int) -> Phase4TaskIntake:
        """Build a typed intake record from one JSON object.

        Parameters
        ----------
        row:
            JSON object from the ``tasks`` array.
        index:
            Zero-based task position, used only for diagnostics.

        Returns
        -------
        Phase4TaskIntake
            Normalised, immutable intake record.

        Raises
        ------
        ValueError
            If any required field is missing or has the wrong JSON type.
        """
        prefix = f"tasks[{index}]"
        strings = {
            field: _required_text(row, field, prefix) for field in _REQUIRED_STRING_FIELDS
        }
        return cls(
            task_id=strings["id"],
            status=strings["status"],
            plan_anchor=strings["plan_anchor"],
            buyer_user_value=strings["buyer_user_value"],
            threat_model=strings["threat_model"],
            required_evidence=_required_text_list(row, "required_evidence", prefix),
            affected_surfaces=_required_text_list(row, "affected_surfaces", prefix),
            benchmark_impact=strings["benchmark_impact"],
            claim_boundary=strings["claim_boundary"],
            implementation_readiness=strings["implementation_readiness"],
            open_blockers=_optional_text_list(row, "open_blockers", prefix),
        )


def validate_phase4_task_intake(path: Path = _DEFAULT_INTAKE) -> list[str]:
    """Return validation failures for the Phase 4 intake ledger.

    Parameters
    ----------
    path:
        JSON ledger path to validate.

    Returns
    -------
    list[str]
        Human-readable validation failures. An empty list means the ledger is
        complete enough to govern Phase 4 implementation intake.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return [f"{path}: cannot load intake ledger: {exc}"]
    if not isinstance(payload, dict):
        return [f"{path}: top-level JSON value must be an object"]
    schema_version = payload.get("schema_version")
    if schema_version != _SCHEMA_VERSION:
        return [f"{path}: schema_version must be {_SCHEMA_VERSION!r}"]
    rows = payload.get("tasks")
    if not isinstance(rows, list) or not rows:
        return [f"{path}: tasks must be a non-empty array"]

    failures: list[str] = []
    seen: set[str] = set()
    for index, raw_row in enumerate(rows):
        if not isinstance(raw_row, dict):
            failures.append(f"tasks[{index}]: task entry must be an object")
            continue
        try:
            task = Phase4TaskIntake.from_mapping(raw_row, index)
        except ValueError as exc:
            failures.append(str(exc))
            continue
        failures.extend(_validate_task(task))
        if task.task_id in seen:
            failures.append(f"{task.task_id}: duplicate task id")
        seen.add(task.task_id)
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Phase 4 task-intake guard."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=_DEFAULT_INTAKE)
    args = parser.parse_args(argv)
    failures = validate_phase4_task_intake(args.input)
    for failure in failures:
        print(f"phase4 intake failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


def _validate_task(task: Phase4TaskIntake) -> list[str]:
    failures: list[str] = []
    if task.status not in _STATUSES:
        failures.append(f"{task.task_id}: invalid status {task.status!r}")
    if not task.plan_anchor.startswith("Phase 4"):
        failures.append(f"{task.task_id}: plan_anchor must start with 'Phase 4'")
    if task.benchmark_impact not in _BENCHMARK_IMPACTS:
        failures.append(
            f"{task.task_id}: invalid benchmark_impact {task.benchmark_impact!r}"
        )
    if (
        task.status in {"ready", "in_progress", "done"}
        and task.implementation_readiness not in _READY_STATES
    ):
        failures.append(
            f"{task.task_id}: active tasks must be ready or executed, not "
            f"{task.implementation_readiness!r}"
        )
    if task.status in {"blocked", "deferred"} and not task.open_blockers:
        failures.append(f"{task.task_id}: blocked/deferred tasks need open_blockers")
    if task.benchmark_impact == "external_required" and (
        "external" not in task.claim_boundary.lower()
        and "comparative" not in task.claim_boundary.lower()
    ):
        failures.append(
            f"{task.task_id}: external benchmark tasks need an external/comparative "
            "claim boundary"
        )
    return failures


def _required_text(row: Mapping[str, object], field: str, prefix: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{prefix}.{field}: required non-empty string")
    return value.strip()


def _required_text_list(
    row: Mapping[str, object],
    field: str,
    prefix: str,
) -> tuple[str, ...]:
    values = _optional_text_list(row, field, prefix)
    if not values:
        raise ValueError(f"{prefix}.{field}: required non-empty string array")
    return values


def _optional_text_list(
    row: Mapping[str, object],
    field: str,
    prefix: str,
) -> tuple[str, ...]:
    value = row.get(field, [])
    if not isinstance(value, list):
        raise ValueError(f"{prefix}.{field}: must be a string array")
    values: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{prefix}.{field}[{index}]: required non-empty string")
        values.append(item.strip())
    return tuple(values)


if __name__ == "__main__":
    raise SystemExit(main())
