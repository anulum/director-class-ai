# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — operator approval transports

"""Operator-facing transports for digest-scoped approvals.

The local :class:`ApprovalQueue` remains the source of truth. This module adds
deployment adapters around that queue without widening what operators or
automation can see: service responses and webhook events expose only ticket
digests, status, timestamps, expiry, and an approver digest. Raw prompts,
actions, context, tool output, and command output never cross these transports.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal, Protocol
from urllib.request import Request, urlopen

from .queue import ApprovalQueue, ApprovalTicket

__all__ = [
    "APPROVAL_AUTH_HEADER",
    "APPROVAL_SIGNATURE_HEADER",
    "ApprovalService",
    "ApprovalServiceConfig",
    "ApprovalServiceResponse",
    "ApprovalWebhookEvent",
    "ApprovalWebhookSink",
    "OperatorApprovalConsole",
    "OperatorApprovalHTTPServer",
]

APPROVAL_AUTH_HEADER = "X-Director-Approval-Key"
APPROVAL_SIGNATURE_HEADER = "X-Director-Approval-Signature"
_Method = Literal["GET", "POST"]


class _UrlOpener(Protocol):
    def __call__(self, request: Request, timeout: float) -> object:
        """Send one prepared request and return the transport response."""


def _urlopen(request: Request, timeout: float) -> object:
    return urlopen(request, timeout=timeout)


@dataclass(frozen=True)
class ApprovalWebhookEvent:
    """Redacted approval event suitable for outbound notification hooks."""

    event_name: str
    ticket: Mapping[str, object]

    def to_json(self) -> bytes:
        """Serialise the webhook event as deterministic UTF-8 JSON."""
        return json.dumps(
            {"event_name": self.event_name, "ticket": dict(self.ticket)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


@dataclass(frozen=True)
class ApprovalWebhookSink:
    """POST redacted approval events to an operator-owned webhook endpoint."""

    url: str
    signing_key: str = ""
    timeout_seconds: float = 5.0
    opener: _UrlOpener = _urlopen

    def publish(self, event: ApprovalWebhookEvent) -> None:
        """Send one redacted approval event to the configured webhook URL."""
        body = event.to_json()
        headers = {"content-type": "application/json; charset=utf-8"}
        if self.signing_key:
            headers[APPROVAL_SIGNATURE_HEADER] = hmac.new(
                self.signing_key.encode("utf-8"),
                body,
                hashlib.sha256,
            ).hexdigest()
        request = Request(self.url, data=body, headers=headers, method="POST")
        self.opener(request, timeout=self.timeout_seconds)


class OperatorApprovalConsole:
    """Small adapter for operator consoles and runbooks."""

    def __init__(
        self,
        queue: ApprovalQueue,
        *,
        webhook_sink: ApprovalWebhookSink | None = None,
    ) -> None:
        self._queue = queue
        self._webhook_sink = webhook_sink

    def pending(self) -> list[Mapping[str, object]]:
        """Return redacted pending-ticket views for operator review."""
        return [_ticket_view(ticket) for ticket in self._queue.pending()]

    def approve(self, digest: str, approver: str) -> Mapping[str, object]:
        """Approve one pending digest and return its redacted ticket view."""
        ticket = self._queue.approve(digest, approver)
        view = _ticket_view(ticket)
        self._publish("director_class_ai.approval.approved", view)
        return view

    def deny(self, digest: str, approver: str) -> Mapping[str, object]:
        """Deny one pending digest and return its redacted ticket view."""
        ticket = self._queue.deny(digest, approver)
        view = _ticket_view(ticket)
        self._publish("director_class_ai.approval.denied", view)
        return view

    def _publish(self, event_name: str, ticket: Mapping[str, object]) -> None:
        if self._webhook_sink is not None:
            self._webhook_sink.publish(ApprovalWebhookEvent(event_name, ticket))


@dataclass(frozen=True)
class ApprovalServiceConfig:
    """Configuration for the local operator-approval HTTP service."""

    operator_key: str
    max_body_bytes: int = 65_536

    def __post_init__(self) -> None:
        if not self.operator_key:
            raise ValueError("operator_key is required")


@dataclass(frozen=True)
class ApprovalServiceResponse:
    """HTTP-ready response from the approval service dispatcher."""

    status: int
    body: Mapping[str, object]
    headers: Mapping[str, str] = field(
        default_factory=lambda: {"content-type": "application/json; charset=utf-8"}
    )

    def to_json(self) -> bytes:
        """Serialise the response body as deterministic UTF-8 JSON."""
        return json.dumps(
            self.body,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class ApprovalService:
    """Loopback dispatcher for digest-scoped operator approvals."""

    def __init__(
        self,
        console: OperatorApprovalConsole,
        *,
        config: ApprovalServiceConfig,
    ) -> None:
        self.console = console
        self.config = config

    def handle(
        self,
        method: _Method,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        operator_key: str = "",
    ) -> ApprovalServiceResponse:
        """Dispatch one parsed approval-service request."""
        if method == "GET" and path == "/healthz":
            return ApprovalServiceResponse(HTTPStatus.OK, {"status": "ok"})
        if not hmac.compare_digest(operator_key, self.config.operator_key):
            return _error(HTTPStatus.UNAUTHORIZED, "unauthorized")
        if method == "GET" and path == "/v1/approvals/pending":
            return ApprovalServiceResponse(
                HTTPStatus.OK,
                {"tickets": list(self.console.pending())},
            )
        if method != "POST":
            return _error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
        if payload is None:
            return _error(HTTPStatus.BAD_REQUEST, "missing_json_body")
        if path == "/v1/approvals/approve":
            return self._decide(payload, approve=True)
        if path == "/v1/approvals/deny":
            return self._decide(payload, approve=False)
        return _error(HTTPStatus.NOT_FOUND, "unknown_endpoint")

    def _decide(
        self,
        payload: Mapping[str, object],
        *,
        approve: bool,
    ) -> ApprovalServiceResponse:
        digest = _string(payload.get("digest"))
        approver = _string(payload.get("approver"))
        if not digest or not approver:
            return _error(HTTPStatus.BAD_REQUEST, "digest_and_approver_required")
        try:
            ticket = (
                self.console.approve(digest, approver)
                if approve
                else self.console.deny(digest, approver)
            )
        except KeyError:
            return _error(HTTPStatus.NOT_FOUND, "ticket_not_found")
        except ValueError:
            return _error(HTTPStatus.CONFLICT, "ticket_not_pending")
        return ApprovalServiceResponse(HTTPStatus.OK, {"ticket": dict(ticket)})


class OperatorApprovalHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server with an attached approval service."""

    def __init__(
        self,
        server_address: tuple[str, int],
        service: ApprovalService,
    ) -> None:
        super().__init__(server_address, _Handler)
        self.service = service


class _Handler(BaseHTTPRequestHandler):
    server: OperatorApprovalHTTPServer

    def log_message(self, format: str, *args: object) -> None:
        """Suppress BaseHTTPRequestHandler stderr logging in embedded use."""
        return None

    def do_GET(self) -> None:
        """Handle service health and pending-ticket requests."""
        self._send(
            self.server.service.handle(
                "GET",
                self.path,
                operator_key=self.headers.get(APPROVAL_AUTH_HEADER, ""),
            )
        )

    def do_POST(self) -> None:
        """Handle JSON approval and denial requests."""
        length = _content_length(self.headers.get("content-length"))
        if length is None or length > self.server.service.config.max_body_bytes:
            self._send(_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large"))
            return
        raw = self.rfile.read(length)
        try:
            loaded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(_error(HTTPStatus.BAD_REQUEST, "invalid_json"))
            return
        if not isinstance(loaded, Mapping):
            self._send(_error(HTTPStatus.BAD_REQUEST, "json_body_must_be_object"))
            return
        self._send(
            self.server.service.handle(
                "POST",
                self.path,
                loaded,
                operator_key=self.headers.get(APPROVAL_AUTH_HEADER, ""),
            )
        )

    def _send(self, response: ApprovalServiceResponse) -> None:
        body = response.to_json()
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _ticket_view(ticket: ApprovalTicket) -> Mapping[str, object]:
    return {
        "digest": ticket.digest,
        "status": ticket.status,
        "created_at": ticket.created_at,
        "decided_at": ticket.decided_at,
        "expires_at": ticket.expires_at,
        "approver_digest": _approver_digest(ticket.approver),
    }


def _approver_digest(approver: str) -> str:
    if not approver:
        return ""
    return hashlib.sha256(approver.encode("utf-8")).hexdigest()


def _content_length(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _error(status: HTTPStatus, code: str) -> ApprovalServiceResponse:
    return ApprovalServiceResponse(status, {"error": code})
