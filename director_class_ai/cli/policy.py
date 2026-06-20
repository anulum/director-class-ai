# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy governance CLI

"""Operator CLI for the Guardrail-as-Code governance workflow.

One ``director-class-policy`` command per lifecycle step, all against a single
durable ledger (``--store``):

    propose   open a candidate posture change for review
    expose    A/B-replay a case corpus under the approved head and a candidate
    approve   commit a pending proposal (a different reviewer)
    deny      reject a pending proposal
    rollback  restore a prior posture as the new head
    drift     check a live posture for divergence from the approved head
    status    summarise the head, lineage length, and pending proposals

Every command loads the ledger, delegates to :class:`PolicyGovernance` (which owns
the gate), saves on success, and prints the result as JSON. A governance error
(self-approval, stale proposal, unknown digest, weak profile) is reported on
stderr with a non-zero exit and leaves the ledger untouched.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections.abc import Callable, Sequence

from ..policy.corpus import load_cases
from ..policy.drift import PolicyDriftEvent
from ..policy.exposure import ExposureReport
from ..policy.governance import PolicyGovernance
from ..policy.loader import load_profile_file
from ..policy.review import PolicyChangeProposal
from ..policy.revision import PolicyRevision
from ..policy.store import serialise_profile


def _now() -> str:
    """Return the current UTC time as an ISO-8601 timestamp."""
    return datetime.datetime.now(datetime.UTC).isoformat()


def _revision_view(revision: PolicyRevision) -> dict[str, object]:
    """Render a revision as a JSON-ready summary."""
    return {
        "digest": revision.digest,
        "parent": revision.parent,
        "author": revision.author,
        "created_at": revision.created_at,
        "reason": revision.reason,
        "profile": serialise_profile(revision.profile),
    }


def _proposal_view(proposal: PolicyChangeProposal) -> dict[str, object]:
    """Render a proposal as a JSON-ready summary."""
    return {
        "digest": proposal.digest,
        "status": proposal.status,
        "reviewer": proposal.reviewer,
        "decided_at": proposal.decided_at,
        "revision": _revision_view(proposal.revision),
    }


def _report_view(report: ExposureReport) -> dict[str, object]:
    """Render an A/B exposure report as a JSON-ready summary."""
    return {
        "outcomes": [
            {
                "label": o.label,
                "baseline": o.baseline,
                "candidate": o.candidate,
                "changed": o.changed,
            }
            for o in report.outcomes
        ],
        "changed": [o.label for o in report.changed],
        "changed_count": report.changed_count,
        "transitions": report.transitions,
    }


def _event_view(event: PolicyDriftEvent) -> dict[str, object]:
    """Render a drift event as a JSON-ready summary."""
    return {
        "approved_digest": event.approved_digest,
        "live_digest": event.live_digest,
        "detected_at": event.detected_at,
        "changes": [
            {"field": c.field, "old": c.old, "new": c.new} for c in event.changes
        ],
    }


def _emit(result: object) -> int:
    """Print ``result`` as indented JSON and return success."""
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _handle_status(args: argparse.Namespace) -> int:
    governance = PolicyGovernance.load(args.store)
    return _emit(governance.status())


def _handle_propose(args: argparse.Namespace) -> int:
    governance = PolicyGovernance.load(args.store)
    profile = load_profile_file(args.profile)
    proposal = governance.propose(
        profile, proposer=args.proposer, created_at=args.at, reason=args.reason
    )
    governance.save(args.store)
    return _emit(_proposal_view(proposal))


def _handle_expose(args: argparse.Namespace) -> int:
    governance = PolicyGovernance.load(args.store)
    candidate = load_profile_file(args.candidate)
    report = governance.expose(candidate, load_cases(args.cases))
    return _emit(_report_view(report))


def _handle_approve(args: argparse.Namespace) -> int:
    governance = PolicyGovernance.load(args.store)
    revision = governance.approve(args.digest, reviewer=args.reviewer, decided_at=args.at)
    governance.save(args.store)
    return _emit(_revision_view(revision))


def _handle_deny(args: argparse.Namespace) -> int:
    governance = PolicyGovernance.load(args.store)
    proposal = governance.deny(args.digest, reviewer=args.reviewer, decided_at=args.at)
    governance.save(args.store)
    return _emit(_proposal_view(proposal))


def _handle_rollback(args: argparse.Namespace) -> int:
    governance = PolicyGovernance.load(args.store)
    revision = governance.rollback(
        args.digest, author=args.author, created_at=args.at, reason=args.reason
    )
    governance.save(args.store)
    return _emit(_revision_view(revision))


def _handle_drift(args: argparse.Namespace) -> int:
    governance = PolicyGovernance.load(args.store)
    live = load_profile_file(args.live)
    event = governance.drift_check(live, detected_at=args.at)
    if event is None:
        return _emit({"drift": False})
    return _emit({"drift": True, "event": _event_view(event)})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="director-class-policy",
        description="Guardrail-as-Code policy governance workflow.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _with_store(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("--store", required=True, help="path to the governance ledger")
        return p

    def _with_at(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("--at", default=None, help="ISO timestamp (defaults to now, UTC)")
        return p

    status = _with_store(sub.add_parser("status", help="summarise the ledger"))
    status.set_defaults(handler=_handle_status)

    propose = _with_at(_with_store(sub.add_parser("propose", help="open a proposal")))
    propose.add_argument("--profile", required=True, help="candidate profile TOML")
    propose.add_argument("--proposer", required=True, help="who proposes the change")
    propose.add_argument("--reason", required=True, help="why the posture changes")
    propose.set_defaults(handler=_handle_propose)

    expose = _with_store(sub.add_parser("expose", help="A/B-replay a case corpus"))
    expose.add_argument("--candidate", required=True, help="candidate profile TOML")
    expose.add_argument("--cases", required=True, help="exposure case corpus JSON")
    expose.set_defaults(handler=_handle_expose)

    approve = _with_at(_with_store(sub.add_parser("approve", help="commit a proposal")))
    approve.add_argument("--digest", required=True, help="proposed posture digest")
    approve.add_argument("--reviewer", required=True, help="who approves (not proposer)")
    approve.set_defaults(handler=_handle_approve)

    deny = _with_at(_with_store(sub.add_parser("deny", help="reject a proposal")))
    deny.add_argument("--digest", required=True, help="proposed posture digest")
    deny.add_argument("--reviewer", required=True, help="who denies the change")
    deny.set_defaults(handler=_handle_deny)

    rollback = _with_at(
        _with_store(sub.add_parser("rollback", help="restore a prior posture"))
    )
    rollback.add_argument("--digest", required=True, help="posture digest to restore")
    rollback.add_argument("--author", required=True, help="who authorises the rollback")
    rollback.add_argument("--reason", required=True, help="why the posture is restored")
    rollback.set_defaults(handler=_handle_rollback)

    drift = _with_at(_with_store(sub.add_parser("drift", help="check live drift")))
    drift.add_argument("--live", required=True, help="live profile TOML")
    drift.set_defaults(handler=_handle_drift)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run the requested governance command, and report."""
    parser = _parser()
    args = parser.parse_args(argv)
    if getattr(args, "at", None) is None and hasattr(args, "at"):
        args.at = _now()
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return handler(args)
    except (ValueError, KeyError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
