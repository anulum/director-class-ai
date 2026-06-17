# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
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

from ..core.governor import digest_request
from ..core.signal import EvaluationRequest

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
    expires_at: float | None = None


class ApprovalQueue:
    """Durable, digest-scoped, single-use approval workflow."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] = time.time,
        ttl_seconds: float = 3600.0,
    ) -> None:
        self.path = Path(path)
        self._clock = clock
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    # ── persistence ────────────────────────────────────────────────────────────
    def _load(self) -> dict[str, ApprovalTicket]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return {d: ApprovalTicket(**t) for d, t in raw.items()}

    def _save(self, tickets: dict[str, ApprovalTicket]) -> None:
        self.path.write_text(
            json.dumps({d: asdict(t) for d, t in tickets.items()}),
            encoding="utf-8",
        )

    def _is_expired(self, ticket: ApprovalTicket) -> bool:
        return ticket.expires_at is not None and self._clock() > ticket.expires_at

    # ── Governor approval hook ───────────────────────────────────────────────────
    def request_approval(self, verdict: object, request: EvaluationRequest) -> bool:
        """Governor hook: consume a valid approval, else open a pending ticket."""
        digest = digest_request(request)
        with self._lock:
            tickets = self._load()
            ticket = tickets.get(digest)
            if ticket and ticket.status == _APPROVED and not self._is_expired(ticket):
                ticket.status = _CONSUMED  # single use
                self._save(tickets)
                return True
            if ticket is None or ticket.status in _TERMINAL or self._is_expired(ticket):
                tickets[digest] = ApprovalTicket(
                    digest=digest, status=_PENDING, created_at=self._clock()
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
        with self._lock:
            tickets = self._load()
            ticket = tickets.get(digest)
            if ticket is None:
                raise KeyError(f"no ticket for digest {digest}")
            if ticket.status != _PENDING:
                raise ValueError(f"ticket {digest} is {ticket.status}, not pending")
            now = self._clock()
            ticket.status = status
            ticket.approver = approver
            ticket.decided_at = now
            ticket.expires_at = (now + self._ttl) if status == _APPROVED else None
            self._save(tickets)
            return ticket

    def get(self, digest: str) -> ApprovalTicket | None:
        """Return one ticket by digest, or None when it is absent."""
        return self._load().get(digest)

    def pending(self) -> list[ApprovalTicket]:
        """Return all tickets still awaiting a human decision."""
        return [t for t in self._load().values() if t.status == _PENDING]
