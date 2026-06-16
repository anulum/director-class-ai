# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — authorised execution workflow tests

from __future__ import annotations

from pathlib import Path

from director_class_ai.workflows import run_authorised_shell_workflow


class _Executor:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, command: str) -> tuple[str, int]:
        self.calls.append(command)
        return ("rows dropped from staging_import", 0)


def test_authorised_destructive_shell_workflow_executes_once(tmp_path: Path) -> None:
    executor = _Executor()

    report = run_authorised_shell_workflow(
        command="DROP TABLE staging_import",
        queue_path=tmp_path / "approvals.json",
        approver="miroslav",
        query="Drop the temporary staging_import table after the migration.",
        executor=executor,
    )

    assert report.initial.permitted is False
    assert report.initial.executed is False
    assert report.initial.decision.escalated is True
    assert report.pending_before_approval == 1

    assert report.approved_digest == report.initial.decision_id
    assert report.approval_status == "approved"

    assert report.approved.permitted is True
    assert report.approved.executed is True
    assert report.approved.exit_code == 0
    assert report.approved.output_digest
    assert executor.calls == ["DROP TABLE staging_import"]

    assert report.replay.permitted is False
    assert report.replay.executed is False
    assert report.replay.decision.escalated is True
    assert executor.calls == ["DROP TABLE staging_import"]

    assert report.consumed_status == "consumed"
    assert report.pending_after_replay == 1
