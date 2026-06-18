# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — Phase 4 task intake tests

from __future__ import annotations

import json
from pathlib import Path

from tools.check_phase4_task_intake import main, validate_phase4_task_intake


def _payload(task: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "director-class-ai.phase4-task-intake.v1",
        "updated_at": "2026-06-18",
        "tasks": [task],
    }


def _task(**overrides: object) -> dict[str, object]:
    task: dict[str, object] = {
        "id": "P4-GATE-001",
        "plan_anchor": "Phase 4 / Realistic high-impact execution order",
        "status": "done",
        "buyer_user_value": "Prevents low-yield Phase 4 work from entering build.",
        "threat_model": "Unscoped detector additions and unsupported claims.",
        "required_evidence": ["validator pass", "focused tests"],
        "affected_surfaces": ["docs/internal/PLAN.md", "tools"],
        "benchmark_impact": "none",
        "claim_boundary": "Internal planning governance only.",
        "implementation_readiness": "executed",
        "open_blockers": [],
    }
    task.update(overrides)
    return task


def _write(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "phase4_task_intake.json"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def test_validate_phase4_task_intake_accepts_complete_active_task(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _payload(_task()))

    assert validate_phase4_task_intake(path) == []
    assert main(("--input", str(path))) == 0


def test_validate_phase4_task_intake_requires_buyer_and_evidence_fields(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        _payload(_task(buyer_user_value="", required_evidence=[])),
    )

    failures = validate_phase4_task_intake(path)

    assert any("buyer_user_value" in failure for failure in failures)


def test_validate_phase4_task_intake_requires_blockers_for_blocked_tasks(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        _payload(
            _task(
                id="P4-BENCH-EXT-001",
                status="blocked",
                benchmark_impact="external_required",
                implementation_readiness="blocked_on_external_inputs",
                open_blockers=[],
                claim_boundary=(
                    "No external comparative claim until reviewed artefacts exist."
                ),
            )
        ),
    )

    failures = validate_phase4_task_intake(path)

    assert any("open_blockers" in failure for failure in failures)


def test_validate_phase4_task_intake_rejects_duplicate_ids(tmp_path: Path) -> None:
    duplicate = _task()
    path = _write(
        tmp_path,
        {
            "schema_version": "director-class-ai.phase4-task-intake.v1",
            "updated_at": "2026-06-18",
            "tasks": [_task(), duplicate],
        },
    )

    failures = validate_phase4_task_intake(path)

    assert any("duplicate task id" in failure for failure in failures)
