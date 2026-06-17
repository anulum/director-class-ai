# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
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
from typing import Literal

from ..sdk import ToolExecutionResult, ToolReviewMiddleware, ToolReviewRequest

__all__ = ["CommandGuardOptions", "build_command_request", "main", "run_guard"]

CommandSurface = Literal["shell", "database", "cloud", "kubernetes", "http", "custom"]


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
    """Review a command and return a redacted decision event."""
    request = build_command_request(options)
    decision = ToolReviewMiddleware.default(executor=_execute_command).run(request)
    event = decision.to_audit_event()
    return {
        **event,
        "surface": options.surface,
        "dry_run": not options.execute,
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
    completed = subprocess.run(  # nosec B602 - reached only after Governor permit
        command,
        shell=True,
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
        "command",
        nargs=argparse.REMAINDER,
        help="Command to review. Use -- before command arguments.",
    )
    return parser


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
