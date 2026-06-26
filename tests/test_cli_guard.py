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
    CommandSurface,
    build_command_request,
    main,
    run_guard,
)
from director_class_ai.policy import PolicyGovernance, Profile

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _opts(
    tmp_path: Path,
    *,
    surface: CommandSurface = "shell",
    command: tuple[str, ...] = ("echo", "ok"),
    provenance: str = "user",
    query: str = "",
    context: str = "",
    tenant_id: str = "",
    execute: bool = False,
    audit_log: str | None = None,
    approval_store: str | None = None,
    policy_store: str | None = None,
    live_profile: str = "",
    require_policy_store: bool = False,
    audit_head_key_env: str = "",
    audit_anchor_log: str = "",
) -> CommandGuardOptions:
    """Build guard options whose runtime state lives under tmp."""
    return CommandGuardOptions(
        surface=surface,
        command=command,
        provenance=provenance,
        query=query,
        context=context,
        tenant_id=tenant_id,
        execute=execute,
        audit_log=audit_log if audit_log is not None else str(tmp_path / "audit.jsonl"),
        approval_store=(
            approval_store
            if approval_store is not None
            else str(tmp_path / "approvals.json")
        ),
        policy_store=(
            policy_store if policy_store is not None else str(tmp_path / "policy.json")
        ),
        live_profile=live_profile,
        require_policy_store=require_policy_store,
        audit_head_key_env=audit_head_key_env,
        audit_anchor_log=audit_anchor_log,
    )


def _main_args(tmp_path: Path, *argv: str) -> tuple[str, ...]:
    return (
        "--audit-log",
        str(tmp_path / "audit.jsonl"),
        "--approval-store",
        str(tmp_path / "approvals.json"),
        "--policy-store",
        str(tmp_path / "policy.json"),
        *argv,
    )


def _profile_toml(path: Path, *, threshold: float) -> Path:
    """Write a runtime policy profile fixture."""
    path.write_text(
        f'name = "staging"\naction_block_threshold = {threshold}\n'
        "uncertainty_margin = 0.0\n",
        encoding="utf-8",
    )
    return path


def _approved_policy_store(path: Path, *, threshold: float) -> None:
    """Write a reviewed Guardrail-as-Code ledger fixture."""
    governance = PolicyGovernance.empty()
    proposal = governance.propose(
        Profile(
            name="staging",
            action_block_threshold=threshold,
            uncertainty_margin=0.0,
        ),
        proposer="alice",
        created_at="t0",
        reason="baseline",
    )
    governance.approve(proposal.digest, reviewer="bob", decided_at="t1")
    governance.save(path)


def test_command_guard_options_parse_defaults() -> None:
    options = CommandGuardOptions.from_argv(("--", "echo", "ok"))

    assert options.surface == "shell"
    assert options.command == ("echo", "ok")
    assert options.provenance == "user"
    assert options.execute is False
    assert options.audit_log == "runtime/audit.jsonl"
    assert options.approval_store == "runtime/approvals.json"
    assert options.policy_store == "runtime/policy.json"
    assert options.live_profile == ""
    assert options.require_policy_store is False


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
        (
            "--audit-log",
            "/tmp/a.jsonl",
            "--approval-store",
            "/tmp/q.json",
            "--policy-store",
            "/tmp/p.json",
            "--",
            "noop",
        )
    )
    assert options.audit_log == "/tmp/a.jsonl"
    assert options.approval_store == "/tmp/q.json"
    assert options.policy_store == "/tmp/p.json"


def test_command_guard_options_parse_runtime_posture_guards() -> None:
    options = CommandGuardOptions.from_argv(
        (
            "--require-policy-store",
            "--live-profile",
            "/tmp/live.toml",
            "--",
            "noop",
        )
    )

    assert options.require_policy_store is True
    assert options.live_profile == "/tmp/live.toml"


def test_command_guard_options_parse_signed_audit_paths() -> None:
    options = CommandGuardOptions.from_argv(
        (
            "--audit-head-key-env",
            "DCA_AUDIT_HEAD_KEY",
            "--audit-anchor-log",
            "/tmp/audit-anchor.jsonl",
            "--",
            "noop",
        )
    )

    assert options.audit_head_key_env == "DCA_AUDIT_HEAD_KEY"
    assert options.audit_anchor_log == "/tmp/audit-anchor.jsonl"


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


def test_command_guard_can_sign_and_anchor_audit_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DCA_AUDIT_HEAD_KEY", "operator-secret")
    audit_log = tmp_path / "audit.jsonl"
    anchor = tmp_path / "anchor.jsonl"

    event = run_guard(
        _opts(
            tmp_path,
            surface="shell",
            command=("echo", "ok"),
            audit_log=str(audit_log),
            audit_head_key_env="DCA_AUDIT_HEAD_KEY",
            audit_anchor_log=str(anchor),
        )
    )

    assert event["route"] == "allow"
    assert audit_log.with_suffix(".jsonl.head.sig").exists()
    assert anchor.exists()
    assert verify_chain(
        audit_log, head_signing_key="operator-secret", anchor_path=anchor
    ).ok


def test_required_policy_store_blocks_without_approved_head(tmp_path: Path) -> None:
    event = run_guard(
        _opts(
            tmp_path,
            surface="shell",
            command=("echo", "ok"),
            require_policy_store=True,
        )
    )

    assert event["route"] == "block"
    assert event["permitted"] is False
    assert event["executed"] is False
    assert event["firing"] == ("policy_head_missing",)
    assert verify_chain(str(event["audit_log"])).ok


def test_policy_store_block_preserves_signed_audit_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DCA_AUDIT_HEAD_KEY", "operator-secret")
    audit_log = tmp_path / "audit.jsonl"
    anchor = tmp_path / "anchor.jsonl"

    event = run_guard(
        _opts(
            tmp_path,
            surface="shell",
            command=("echo", "ok"),
            audit_log=str(audit_log),
            require_policy_store=True,
            audit_head_key_env="DCA_AUDIT_HEAD_KEY",
            audit_anchor_log=str(anchor),
        )
    )

    assert event["route"] == "block"
    assert verify_chain(
        audit_log, head_signing_key="operator-secret", anchor_path=anchor
    ).ok


def test_drifted_live_profile_blocks_before_review(tmp_path: Path) -> None:
    policy_store = tmp_path / "policy.json"
    live_profile = _profile_toml(tmp_path / "live.toml", threshold=0.9)
    _approved_policy_store(policy_store, threshold=0.3)

    event = run_guard(
        _opts(
            tmp_path,
            surface="shell",
            command=("echo", "ok"),
            policy_store=str(policy_store),
            live_profile=str(live_profile),
        )
    )

    assert event["route"] == "block"
    assert event["permitted"] is False
    assert event["executed"] is False
    assert event["firing"] == ("policy_runtime_drift",)
    assert event["policy_drift"]["changes"] == ("action_block_threshold",)
    assert verify_chain(str(event["audit_log"])).ok


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
