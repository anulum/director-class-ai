# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — durable approval queue

"""A file-backed approval queue for escalated actions.

The Governor's approval hook is the right seam, but a callable that answers
yes/no synchronously is not how a human approves a destructive action. This queue
turns escalation into a durable workflow: an escalated request creates a *pending*
ticket bound to its request digest; a human later approves or denies it with
identity and a timestamp; and the approval is **single-use and digest-scoped** — it
permits exactly one execution of exactly that action, never a different one and
never twice. Approvals expire, so a stale yes cannot be replayed later.

`request_approval` has the Governor approval-hook signature, so it drops straight
in: first call escalates (blocked, ticket pending), and once a human approves, the
next review of the same action consumes the ticket and permits it.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

from ..core.durability import atomic_write_text
from ..core.governor import digest_request
from ..core.signal import EvaluationRequest
from .policy import ApprovalPolicy

__all__ = ["ApprovalTicket", "ApprovalQueue"]

_PENDING = "pending"
_APPROVED = "approved"
_DENIED = "denied"
_CONSUMED = "consumed"
_EXPIRED = "expired"
_TERMINAL = frozenset({_DENIED, _CONSUMED, _EXPIRED})


@dataclass
class ApprovalTicket:
    """One human-approval ticket, bound to a single action digest."""

    digest: str
    status: str
    created_at: float
    decided_at: float | None = None
    approver: str = ""
    approvers: tuple[str, ...] = ()
    required_approvals: int = 1
    expires_at: float | None = None


class ApprovalQueue:
    """Durable, digest-scoped, single-use approval workflow."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        ttl_seconds: float = 3600.0,
        approval_policy: ApprovalPolicy | None = None,
    ) -> None:
        self.path = Path(path)
        self._clock = clock
        self._ttl = ttl_seconds
        self._approval_policy = approval_policy or ApprovalPolicy()
        self._lock = threading.Lock()

    # ── persistence ────────────────────────────────────────────────────────────
    def _load(self) -> dict[str, ApprovalTicket]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("approval queue must be a JSON object")
        tickets: dict[str, ApprovalTicket] = {}
        for digest, value in raw.items():
            if not isinstance(digest, str) or not isinstance(value, dict):
                raise ValueError("approval queue entries must be ticket objects")
            data = cast("dict[str, object]", value)
            approvers = _string_tuple(data.get("approvers"))
            approver = _string(data.get("approver"))
            if (
                not approvers
                and approver
                and data.get("status")
                in {
                    _APPROVED,
                    _CONSUMED,
                }
            ):
                approvers = (approver,)
            required = _positive_int(data.get("required_approvals"), default=1)
            tickets[digest] = ApprovalTicket(
                digest=digest,
                status=_string(data.get("status")),
                created_at=_float(data.get("created_at")),
                decided_at=_optional_float(data.get("decided_at")),
                approver=approver,
                approvers=approvers,
                required_approvals=required,
                expires_at=_optional_float(data.get("expires_at")),
            )
        return tickets

    def _save(self, tickets: dict[str, ApprovalTicket]) -> None:
        # atomic + fsync: a crash mid-write must not corrupt or empty the queue
        # and lose every outstanding approval.
        atomic_write_text(
            self.path,
            json.dumps({d: asdict(t) for d, t in tickets.items()}),
        )

    def _is_expired(self, ticket: ApprovalTicket) -> bool:
        return ticket.expires_at is not None and self._clock() > ticket.expires_at

    # ── Governor approval hook ───────────────────────────────────────────────────
    def request_approval(self, verdict: object, request: EvaluationRequest) -> bool:
        """Governor hook: consume a valid approval, else open a pending ticket."""
        digest = digest_request(request)
        required_approvals = self._approval_policy.required_approvals(verdict)
        with self._lock:
            tickets = self._load()
            ticket = tickets.get(digest)
            if ticket and ticket.required_approvals < required_approvals:
                ticket.required_approvals = required_approvals
                self._save(tickets)
            if (
                ticket
                and ticket.status == _APPROVED
                and len(ticket.approvers) >= ticket.required_approvals
                and not self._is_expired(ticket)
            ):
                ticket.status = _CONSUMED  # single use
                self._save(tickets)
                return True
            if ticket is None or ticket.status in _TERMINAL or self._is_expired(ticket):
                tickets[digest] = ApprovalTicket(
                    digest=digest,
                    status=_PENDING,
                    created_at=self._clock(),
                    required_approvals=required_approvals,
                )
                self._save(tickets)
            return False

    # ── human actions ─────────────────────────────────────────────────────────
    def approve(self, digest: str, approver: str) -> ApprovalTicket:
        """Approve one pending ticket and set its expiry."""
        return self._decide(digest, _APPROVED, approver)

    def deny(self, digest: str, approver: str) -> ApprovalTicket:
        """Deny one pending ticket without making it executable."""
        return self._decide(digest, _DENIED, approver)

    def _decide(self, digest: str, status: str, approver: str) -> ApprovalTicket:
        if not approver.strip():
            raise ValueError("approver is required")
        with self._lock:
            tickets = self._load()
            ticket = tickets.get(digest)
            if ticket is None:
                raise KeyError(f"no ticket for digest {digest}")
            if ticket.status != _PENDING:
                raise ValueError(f"ticket {digest} is {ticket.status}, not pending")
            if status == _APPROVED and approver in ticket.approvers:
                raise ValueError(f"ticket {digest} already approved by {approver}")
            now = self._clock()
            ticket.approver = approver
            if status == _APPROVED:
                ticket.approvers = (*ticket.approvers, approver)
                ticket.status = (
                    _APPROVED
                    if len(ticket.approvers) >= ticket.required_approvals
                    else _PENDING
                )
            else:
                ticket.status = status
            ticket.decided_at = now
            ticket.expires_at = (now + self._ttl) if ticket.status == _APPROVED else None
            self._save(tickets)
            return ticket

    def get(self, digest: str) -> ApprovalTicket | None:
        """Return one ticket by digest, or None when it is absent."""
        return self._load().get(digest)

    def pending(self) -> list[ApprovalTicket]:
        """Return all tickets still awaiting a human decision."""
        return [t for t in self._load().values() if t.status == _PENDING]


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _string_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    if isinstance(value, tuple):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _float(value: object) -> float:
    return float(value) if isinstance(value, int | float) else 0.0


def _optional_float(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) else None


def _positive_int(value: object, *, default: int) -> int:
    if isinstance(value, int) and value > 0:
        return value
    return default
