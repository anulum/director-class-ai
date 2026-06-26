# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — human approval CLI

"""Operator CLI for the durable, digest-scoped action approval queue.

When the command guard escalates an action it opens a pending ticket bound to the
action's request digest. A human resolves it out of band with this command:

    pending   list the tickets awaiting a decision
    approve   approve a ticket by digest (single-use; permits one later --execute)
    deny      deny a ticket by digest
    show      print one ticket's current state

Every command operates on a single durable queue file (``--store``), prints the
ticket as JSON, and exits non-zero on an unknown or already-decided digest without
mutating the queue.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence

from ..approvals import ApprovalQueue, ApprovalTicket

DEFAULT_APPROVAL_STORE = "runtime/approvals.json"


def _ticket_view(ticket: ApprovalTicket) -> dict[str, object]:
    """Render an approval ticket as a JSON-ready summary."""
    return {
        "digest": ticket.digest,
        "status": ticket.status,
        "approver": ticket.approver,
        "required_approvals": ticket.required_approvals,
        "approval_count": len(ticket.approvers),
        "created_at": ticket.created_at,
        "decided_at": ticket.decided_at,
        "expires_at": ticket.expires_at,
    }


def _emit(result: object) -> int:
    """Print ``result`` as indented JSON and return success."""
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _handle_pending(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    return _emit([_ticket_view(t) for t in queue.pending()])


def _handle_approve(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    return _emit(_ticket_view(queue.approve(args.digest, args.approver)))


def _handle_deny(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    return _emit(_ticket_view(queue.deny(args.digest, args.approver)))


def _handle_show(args: argparse.Namespace, queue: ApprovalQueue) -> int:
    ticket = queue.get(args.digest)
    if ticket is None:
        print(f"error: no ticket for digest {args.digest!r}", file=sys.stderr)
        return 1
    return _emit(_ticket_view(ticket))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="director-class-approve",
        description="Resolve escalated action-approval tickets.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _with_store(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument(
            "--store",
            default=DEFAULT_APPROVAL_STORE,
            help=f"approval queue path. Default: {DEFAULT_APPROVAL_STORE}.",
        )
        return p

    pending = _with_store(sub.add_parser("pending", help="list pending tickets"))
    pending.set_defaults(handler=_handle_pending)

    approve = _with_store(sub.add_parser("approve", help="approve a ticket"))
    approve.add_argument("--digest", required=True, help="action request digest")
    approve.add_argument("--approver", required=True, help="approving identity")
    approve.set_defaults(handler=_handle_approve)

    deny = _with_store(sub.add_parser("deny", help="deny a ticket"))
    deny.add_argument("--digest", required=True, help="action request digest")
    deny.add_argument("--approver", required=True, help="denying identity")
    deny.set_defaults(handler=_handle_deny)

    show = _with_store(sub.add_parser("show", help="show one ticket"))
    show.add_argument("--digest", required=True, help="action request digest")
    show.set_defaults(handler=_handle_show)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run the requested approval command, and report."""
    args = _parser().parse_args(argv)
    queue = ApprovalQueue(args.store)
    handler: Callable[[argparse.Namespace, ApprovalQueue], int] = args.handler
    try:
        return handler(args, queue)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
