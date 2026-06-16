# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — authorised destructive execution workflow

"""End-to-end proof path for authorised destructive shell actions.

The workflow keeps the real effector injected. It demonstrates the runtime
contract without touching a shell: the first review opens a pending approval and
does not execute, the named approval permits one non-dry-run execution, and a
replay is routed back to review with a fresh pending ticket.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..action import (
    BlastRadiusDetector,
    DestructiveCommandDetector,
    OriginTaintDetector,
    ReversibilityDetector,
)
from ..approvals import ApprovalQueue
from ..core import Governor, ParallelEnsembleScorer
from ..effectors import EffectorResult, ShellEffectorAdapter

__all__ = ["AuthorisedShellWorkflowReport", "run_authorised_shell_workflow"]


@dataclass(frozen=True)
class AuthorisedShellWorkflowReport:
    """Privacy-preserving summary of an approval-gated shell execution."""

    initial: EffectorResult
    approved: EffectorResult
    replay: EffectorResult
    approved_digest: str
    approval_status: str
    consumed_status: str
    pending_before_approval: int
    pending_after_replay: int


def run_authorised_shell_workflow(
    *,
    command: str,
    queue_path: str | Path,
    approver: str,
    query: str = "",
    context: str = "",
    executor: Callable[[str], tuple[str, int]],
) -> AuthorisedShellWorkflowReport:
    """Run one authorised destructive command through the full approval path."""

    queue = ApprovalQueue(queue_path)
    governor = Governor(_action_ensemble(), approval=queue.request_approval)
    shell = ShellEffectorAdapter(governor, execute=executor)

    initial = shell.run_command(
        command,
        provenance="user",
        query=query,
        context=context,
        dry_run=True,
    )
    pending_before_approval = len(queue.pending())

    approved_ticket = queue.approve(initial.decision_id, approver)
    approved = shell.run_command(
        command,
        provenance="user",
        query=query,
        context=context,
        dry_run=False,
    )
    consumed_ticket = queue.get(initial.decision_id)
    consumed_status = consumed_ticket.status if consumed_ticket is not None else ""

    replay = shell.run_command(
        command,
        provenance="user",
        query=query,
        context=context,
        dry_run=False,
    )

    return AuthorisedShellWorkflowReport(
        initial=initial,
        approved=approved,
        replay=replay,
        approved_digest=approved_ticket.digest,
        approval_status=approved_ticket.status,
        consumed_status=consumed_status,
        pending_before_approval=pending_before_approval,
        pending_after_replay=len(queue.pending()),
    )


def _action_ensemble() -> ParallelEnsembleScorer:
    return ParallelEnsembleScorer(
        [
            DestructiveCommandDetector(),
            BlastRadiusDetector(),
            OriginTaintDetector(),
            ReversibilityDetector(),
        ]
    )
