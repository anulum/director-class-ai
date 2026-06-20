# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — command guard CLI tests

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from director_class_ai.approvals import ApprovalQueue
from director_class_ai.audit import verify_chain
from director_class_ai.cli.guard import (
    CommandGuardOptions,
    build_command_request,
    main,
    run_guard,
)

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _opts(tmp_path: Path, **kwargs: object) -> CommandGuardOptions:
    """Build guard options whose audit log and approval queue live under tmp."""
    return CommandGuardOptions(
        audit_log=str(tmp_path / "audit.jsonl"),
        approval_store=str(tmp_path / "approvals.json"),
        **kwargs,  # type: ignore[arg-type]
    )


def _main_args(tmp_path: Path, *argv: str) -> tuple[str, ...]:
    return (
        "--audit-log",
        str(tmp_path / "audit.jsonl"),
        "--approval-store",
        str(tmp_path / "approvals.json"),
        *argv,
    )


def test_command_guard_options_parse_defaults() -> None:
    options = CommandGuardOptions.from_argv(("--", "echo", "ok"))

    assert options.surface == "shell"
    assert options.command == ("echo", "ok")
    assert options.provenance == "user"
    assert options.execute is False
    assert options.audit_log == "runtime/audit.jsonl"
    assert options.approval_store == "runtime/approvals.json"


def test_command_guard_options_parse_without_separator() -> None:
    options = CommandGuardOptions.from_argv(("echo", "ok"))

    assert options.command == ("echo", "ok")


def test_command_guard_options_parse_all_surfaces() -> None:
    for surface in ("shell", "database", "cloud", "kubernetes", "http", "custom"):
        options = CommandGuardOptions.from_argv(
            ("--surface", surface, "--provenance", "retrieved", "--", "noop")
        )
        assert options.surface == surface
        assert options.provenance == "retrieved"


def test_command_guard_options_parse_audit_and_approval_paths() -> None:
    options = CommandGuardOptions.from_argv(
        ("--audit-log", "/tmp/a.jsonl", "--approval-store", "/tmp/q.json", "--", "noop")
    )
    assert options.audit_log == "/tmp/a.jsonl"
    assert options.approval_store == "/tmp/q.json"


def test_build_command_request_uses_existing_sdk_contract() -> None:
    options = CommandGuardOptions(
        surface="kubernetes",
        command=("kubectl", "get", "pods"),
        query="list pods",
        tenant_id="tenant-a",
    )

    request = build_command_request(options)
    evaluation = request.to_evaluation()

    assert request.tool_name == "kubernetes.command"
    assert request.arguments == {"command": "kubectl get pods"}
    assert request.action == "kubectl get pods"
    assert request.dry_run is True
    assert evaluation.metadata["surface"] == "kubernetes"
    assert evaluation.tenant_id == "tenant-a"


def test_dry_run_allows_safe_command_without_execution(tmp_path: Path) -> None:
    event = run_guard(_opts(tmp_path, surface="shell", command=("echo", "ok")))

    assert event["route"] == "allow"
    assert event["permitted"] is True
    assert event["executed"] is False
    assert event["dry_run"] is True
    assert event["surface"] == "shell"


def test_blocked_command_returns_redacted_event(tmp_path: Path) -> None:
    event = run_guard(_opts(tmp_path, surface="shell", command=("rm", "-rf", "/")))

    assert event["route"] == "human"
    assert event["permitted"] is False
    assert event["executed"] is False
    assert "destructive_command" in event["firing"]
    assert "rm -rf" not in repr(event)


def test_untrusted_cloud_mutation_blocks_without_approval_downgrade(
    tmp_path: Path,
) -> None:
    event = run_guard(
        _opts(
            tmp_path,
            surface="cloud",
            command=("deploy", "production"),
            provenance="retrieved",
            execute=True,
        )
    )

    assert event["route"] == "block"
    assert event["permitted"] is False
    assert event["executed"] is False
    assert "origin_taint" in event["firing"]


def test_execute_runs_only_after_permit(tmp_path: Path) -> None:
    event = run_guard(
        _opts(tmp_path, surface="shell", command=("printf", "guard-ok"), execute=True)
    )

    assert event["route"] == "allow"
    assert event["permitted"] is True
    assert event["executed"] is True
    assert event["output_digest"]
    assert event["output_size"] > 0
    assert event["exit_code"] == 0
    assert "guard-ok" not in repr(event)


def test_every_decision_is_recorded_to_the_audit_chain(tmp_path: Path) -> None:
    event = run_guard(_opts(tmp_path, surface="shell", command=("echo", "ok")))

    audit_log = Path(str(event["audit_log"]))
    assert audit_log.exists()
    verification = verify_chain(audit_log)
    assert verification.ok
    assert len(audit_log.read_text(encoding="utf-8").splitlines()) == 1


def test_escalated_action_opens_a_pending_ticket(tmp_path: Path) -> None:
    event = run_guard(_opts(tmp_path, surface="shell", command=("rm", "-rf", "/")))

    queue = ApprovalQueue(str(event["approval_store"]))
    digest = str(event["request_digest"])
    ticket = queue.get(digest)
    assert ticket is not None
    assert ticket.status == "pending"
    assert [t.digest for t in queue.pending()] == [digest]


def test_human_approval_permits_the_action_exactly_once(tmp_path: Path) -> None:
    first = run_guard(_opts(tmp_path, surface="shell", command=("rm", "-rf", "/")))
    assert first["permitted"] is False

    queue = ApprovalQueue(str(first["approval_store"]))
    queue.approve(str(first["request_digest"]), "operator@example.com")

    second = run_guard(_opts(tmp_path, surface="shell", command=("rm", "-rf", "/")))
    assert second["permitted"] is True  # the approved digest is consumed once

    third = run_guard(_opts(tmp_path, surface="shell", command=("rm", "-rf", "/")))
    assert third["permitted"] is False  # single-use: a fresh review is blocked again


def test_main_writes_json_and_returns_zero_for_dry_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(_main_args(tmp_path, "--", "echo", "ok"))
    event = json.loads(capsys.readouterr().out)

    assert code == 0
    assert event["route"] == "allow"
    assert event["executed"] is False


def test_main_returns_two_for_unpermitted_action(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(_main_args(tmp_path, "--", "rm", "-rf", "/"))
    event = json.loads(capsys.readouterr().out)

    assert code == 2
    assert event["permitted"] is False


def test_main_returns_executed_command_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(_main_args(tmp_path, "--execute", "--", "false"))
    event = json.loads(capsys.readouterr().out)

    assert code == 1
    assert event["executed"] is True
    assert event["exit_code"] == 1


def test_console_script_is_declared() -> None:
    with _PYPROJECT.open("rb") as handle:
        project = tomllib.load(handle)["project"]

    assert project["scripts"]["director-class-guard"] == (
        "director_class_ai.cli.guard:main"
    )
