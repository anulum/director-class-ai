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

from director_class_ai.cli.guard import (
    CommandGuardOptions,
    build_command_request,
    main,
    run_guard,
)

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_command_guard_options_parse_defaults() -> None:
    options = CommandGuardOptions.from_argv(("--", "echo", "ok"))

    assert options.surface == "shell"
    assert options.command == ("echo", "ok")
    assert options.provenance == "user"
    assert options.execute is False


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


def test_dry_run_allows_safe_command_without_execution() -> None:
    event = run_guard(CommandGuardOptions(surface="shell", command=("echo", "ok")))

    assert event["route"] == "allow"
    assert event["permitted"] is True
    assert event["executed"] is False
    assert event["dry_run"] is True
    assert event["surface"] == "shell"


def test_blocked_command_returns_redacted_event() -> None:
    event = run_guard(CommandGuardOptions(surface="shell", command=("rm", "-rf", "/")))

    assert event["route"] == "human"
    assert event["permitted"] is False
    assert event["executed"] is False
    assert "destructive_command" in event["firing"]
    assert "rm -rf" not in repr(event)


def test_untrusted_cloud_mutation_blocks_without_approval_downgrade() -> None:
    event = run_guard(
        CommandGuardOptions(
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


def test_execute_runs_only_after_permit() -> None:
    event = run_guard(
        CommandGuardOptions(surface="shell", command=("printf", "guard-ok"), execute=True)
    )

    assert event["route"] == "allow"
    assert event["permitted"] is True
    assert event["executed"] is True
    assert event["output_digest"]
    assert event["output_size"] > 0
    assert event["exit_code"] == 0
    assert "guard-ok" not in repr(event)


def test_main_writes_json_and_returns_zero_for_dry_run(capsys) -> None:
    code = main(("--", "echo", "ok"))
    captured = capsys.readouterr()
    event = json.loads(captured.out)

    assert code == 0
    assert event["route"] == "allow"
    assert event["executed"] is False


def test_main_returns_two_for_unpermitted_action(capsys) -> None:
    code = main(("--", "rm", "-rf", "/"))
    event = json.loads(capsys.readouterr().out)

    assert code == 2
    assert event["permitted"] is False


def test_main_returns_executed_command_exit_code(capsys) -> None:
    code = main(("--execute", "--", "false"))
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
