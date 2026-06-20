# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — generic command guard CLI

"""Console guard for shell, database, cloud, Kubernetes, and HTTP commands."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..approvals import ApprovalQueue
from ..audit import AuditChainSink
from ..core.fusion import FusionPolicy
from ..policy import PolicyGovernance
from ..sdk import ToolExecutionResult, ToolReviewMiddleware, ToolReviewRequest

__all__ = ["CommandGuardOptions", "build_command_request", "main", "run_guard"]

CommandSurface = Literal["shell", "database", "cloud", "kubernetes", "http", "custom"]

DEFAULT_AUDIT_LOG = "runtime/audit.jsonl"
DEFAULT_APPROVAL_STORE = "runtime/approvals.json"
DEFAULT_POLICY_STORE = "runtime/policy.json"


def _resolve_runtime_policy(policy_store: str) -> FusionPolicy | None:
    """Return the approved-head fusion policy from a governance ledger.

    The guard enforces the posture an operator has actually approved: when the
    ledger has an approved head its fusion policy governs this decision; with no
    ledger or no approved posture the ensemble keeps its fail-closed defaults.
    """
    return PolicyGovernance.load(policy_store).active_fusion_policy()


@dataclass(frozen=True)
class CommandGuardOptions:
    """Runtime options for the command-line action guard."""

    surface: CommandSurface
    command: tuple[str, ...]
    provenance: str = "user"
    query: str = ""
    context: str = ""
    tenant_id: str = ""
    execute: bool = False
    audit_log: str = DEFAULT_AUDIT_LOG
    approval_store: str = DEFAULT_APPROVAL_STORE
    policy_store: str = DEFAULT_POLICY_STORE

    @classmethod
    def from_argv(cls, argv: Sequence[str] | None = None) -> CommandGuardOptions:
        """Parse command-line arguments into command-guard options."""
        args = _parser().parse_args(argv)
        command = tuple(args.command)
        if command[:1] == ("--",):
            command = command[1:]
        return cls(
            surface=args.surface,
            command=command,
            provenance=args.provenance,
            query=args.query,
            context=args.context,
            tenant_id=args.tenant_id,
            execute=args.execute,
            audit_log=args.audit_log,
            approval_store=args.approval_store,
            policy_store=args.policy_store,
        )


def build_command_request(options: CommandGuardOptions) -> ToolReviewRequest:
    """Build a generic SDK tool-review request for a command-like action."""
    command = " ".join(options.command).strip()
    return ToolReviewRequest(
        tool_name=f"{options.surface}.command",
        arguments={"command": command},
        action=command,
        provenance=options.provenance,
        query=options.query,
        context=options.context,
        tenant_id=options.tenant_id,
        dry_run=not options.execute,
        argument_provenance={"command": options.provenance},
        metadata={"surface": options.surface},
    )


def run_guard(options: CommandGuardOptions) -> dict[str, object]:
    """Review a command and return a redacted decision event.

    Every decision is appended to the tamper-evident hash-chained audit log, and
    an escalated (human-required) action is routed through the durable, digest-
    scoped approval queue: the first review opens a pending ticket and is not
    permitted; once a human approves that digest out of band (``director-class-
    approve``), a single later run with ``--execute`` is permitted exactly once.
    """
    request = build_command_request(options)
    Path(options.audit_log).parent.mkdir(parents=True, exist_ok=True)
    Path(options.approval_store).parent.mkdir(parents=True, exist_ok=True)
    middleware = ToolReviewMiddleware.default(
        policy=_resolve_runtime_policy(options.policy_store),
        executor=_execute_command,
        approval=ApprovalQueue(options.approval_store).request_approval,
        audit_sink=AuditChainSink(Path(options.audit_log)),
    )
    decision = middleware.run(request)
    event = decision.to_audit_event()
    return {
        **event,
        "surface": options.surface,
        "dry_run": not options.execute,
        "audit_log": options.audit_log,
        "approval_store": options.approval_store,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command guard and write a JSON decision to stdout."""
    options = CommandGuardOptions.from_argv(argv)
    event = run_guard(options)
    sys.stdout.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    if event["executed"]:
        exit_code = event.get("exit_code")
        return exit_code if isinstance(exit_code, int) else 0
    return 0 if event["permitted"] else 2


def _execute_command(request: ToolReviewRequest) -> ToolExecutionResult:
    command = request.action
    completed = subprocess.run(  # nosec B602  # nosemgrep — post-permit executor
        command,
        shell=True,  # nosemgrep — post-permit executor
        capture_output=True,
        text=True,
        check=False,
    )
    return ToolExecutionResult(completed.stdout + completed.stderr, completed.returncode)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="director-class-guard",
        description="Review shell, database, cloud, Kubernetes, and HTTP commands.",
    )
    parser.add_argument(
        "--surface",
        choices=("shell", "database", "cloud", "kubernetes", "http", "custom"),
        default="shell",
        help="Command surface being guarded. Default: shell.",
    )
    parser.add_argument(
        "--provenance",
        default="user",
        help="Origin of the proposed action. Default: user.",
    )
    parser.add_argument(
        "--query",
        default="",
        help="User task or intent that produced the command.",
    )
    parser.add_argument(
        "--context",
        default="",
        help="Context used to derive the command.",
    )
    parser.add_argument(
        "--tenant-id",
        default="",
        help="Tenant identifier for the review request.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute only after a permit decision. Omit for dry-run review.",
    )
    parser.add_argument(
        "--audit-log",
        default=DEFAULT_AUDIT_LOG,
        help=f"Tamper-evident hash-chained audit log. Default: {DEFAULT_AUDIT_LOG}.",
    )
    parser.add_argument(
        "--approval-store",
        default=DEFAULT_APPROVAL_STORE,
        help=f"Durable digest-scoped approval queue. Default: {DEFAULT_APPROVAL_STORE}.",
    )
    parser.add_argument(
        "--policy-store",
        default=DEFAULT_POLICY_STORE,
        help=(
            "Guardrail-as-Code ledger whose approved head posture governs this "
            f"review. Default: {DEFAULT_POLICY_STORE} (safe defaults if absent)."
        ),
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to review. Use -- before command arguments.",
    )
    return parser


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
