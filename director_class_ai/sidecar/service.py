# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — halt sidecar loopback service

"""Loopback JSON service that owns the halt-switch state."""

from __future__ import annotations

import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Literal

from .state import HaltSwitchSnapshot, LocalHaltSwitch

__all__ = [
    "HALT_AUTH_HEADER",
    "HaltSwitchHTTPServer",
    "HaltSwitchService",
    "HaltSwitchServiceConfig",
    "HaltSwitchServiceResponse",
]

HALT_AUTH_HEADER = "X-Director-Halt-Key"
_Method = Literal["GET", "POST"]


@dataclass(frozen=True)
class HaltSwitchServiceConfig:
    """Configuration for the operator-owned halt sidecar service."""

    operator_key: str
    max_body_bytes: int = 65_536

    def __post_init__(self) -> None:
        """Reject service configurations without an operator key."""
        if not self.operator_key:
            raise ValueError("operator_key is required")


@dataclass(frozen=True)
class HaltSwitchServiceResponse:
    """HTTP-ready response from the halt-switch sidecar dispatcher."""

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


class HaltSwitchService:
    """Operator-key-protected dispatcher for halt/resume/status operations."""

    def __init__(
        self,
        switch: LocalHaltSwitch,
        *,
        config: HaltSwitchServiceConfig,
    ) -> None:
        self.switch = switch
        self.config = config

    def handle(
        self,
        method: _Method,
        path: str,
        payload: Mapping[str, object] | None = None,
        *,
        operator_key: str = "",
    ) -> HaltSwitchServiceResponse:
        """Dispatch one parsed sidecar request."""
        if method == "GET" and path == "/healthz":
            return HaltSwitchServiceResponse(HTTPStatus.OK, {"status": "ok"})
        if not hmac.compare_digest(operator_key, self.config.operator_key):
            return _error(HTTPStatus.UNAUTHORIZED, "unauthorized")
        if method == "GET" and path == "/v1/halt":
            return HaltSwitchServiceResponse(
                HTTPStatus.OK, _snapshot_view(self.switch.snapshot())
            )
        if method != "POST":
            return _error(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
        if payload is None:
            return _error(HTTPStatus.BAD_REQUEST, "missing_json_body")
        if path == "/v1/halt":
            return self._set(payload, halted=True)
        if path == "/v1/resume":
            return self._set(payload, halted=False)
        return _error(HTTPStatus.NOT_FOUND, "unknown_endpoint")

    def _set(
        self,
        payload: Mapping[str, object],
        *,
        halted: bool,
    ) -> HaltSwitchServiceResponse:
        reason = _string(payload.get("reason"))
        actor = _string(payload.get("actor"))
        try:
            snapshot = (
                self.switch.halt(reason=reason, actor=actor)
                if halted
                else self.switch.resume(reason=reason, actor=actor)
            )
        except ValueError as exc:
            return _error(HTTPStatus.BAD_REQUEST, str(exc))
        return HaltSwitchServiceResponse(HTTPStatus.OK, _snapshot_view(snapshot))


class HaltSwitchHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server with an attached halt-switch service."""

    def __init__(
        self,
        server_address: tuple[str, int],
        service: HaltSwitchService,
    ) -> None:
        super().__init__(server_address, _Handler)
        self.service = service


class _Handler(BaseHTTPRequestHandler):
    server: HaltSwitchHTTPServer

    def log_message(self, format: str, *args: object) -> None:
        """Suppress BaseHTTPRequestHandler stderr logging in embedded use."""
        return None

    def do_GET(self) -> None:
        """Handle service health and halt-status requests."""
        self._send(
            self.server.service.handle(
                "GET",
                self.path,
                operator_key=self.headers.get(HALT_AUTH_HEADER, ""),
            )
        )

    def do_POST(self) -> None:
        """Handle JSON halt and resume requests."""
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
                operator_key=self.headers.get(HALT_AUTH_HEADER, ""),
            )
        )

    def _send(self, response: HaltSwitchServiceResponse) -> None:
        body = response.to_json()
        self.send_response(response.status)
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _snapshot_view(snapshot: HaltSwitchSnapshot) -> dict[str, object]:
    return {
        "halted": snapshot.halted,
        "reason": snapshot.reason,
        "actor": snapshot.actor,
        "updated_at": snapshot.updated_at,
        "generation": snapshot.generation,
    }


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


def _error(status: HTTPStatus, code: str) -> HaltSwitchServiceResponse:
    return HaltSwitchServiceResponse(status, {"error": code})
