# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval transport tests

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from director_class_ai.approvals import (
    APPROVAL_AUTH_HEADER,
    APPROVAL_SIGNATURE_HEADER,
    ApprovalQueue,
    ApprovalService,
    ApprovalServiceConfig,
    ApprovalWebhookEvent,
    ApprovalWebhookSink,
    OperatorApprovalConsole,
    OperatorApprovalHTTPServer,
)
from director_class_ai.approvals.transport import _content_length
from director_class_ai.core import EvaluationRequest


class _Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        self.t += 1.0
        return self.t


class _CaptureOpener:
    def __init__(self) -> None:
        self.requests: list[Request] = []
        self.timeouts: list[float] = []

    def __call__(self, request: Request, timeout: float) -> object:
        self.requests.append(request)
        self.timeouts.append(timeout)
        return object()


def _request(action: str = "rm -rf /private") -> EvaluationRequest:
    return EvaluationRequest(query="clean workspace", action=action)


def _queue(path: Path) -> ApprovalQueue:
    return ApprovalQueue(path, clock=_Clock(), ttl_seconds=30.0)


def _pending_digest(queue: ApprovalQueue) -> str:
    queue.request_approval(None, _request())
    return queue.pending()[0].digest


def test_console_lists_pending_tickets_without_raw_action(tmp_path: Path) -> None:
    queue = _queue(tmp_path / "approvals.json")
    _pending_digest(queue)

    pending = OperatorApprovalConsole(queue).pending()

    assert len(pending) == 1
    assert pending[0]["status"] == "pending"
    assert pending[0]["digest"]
    assert "rm -rf" not in repr(pending)
    assert "private" not in repr(pending)


def test_console_approval_returns_approver_digest_and_consumes(
    tmp_path: Path,
) -> None:
    queue = _queue(tmp_path / "approvals.json")
    digest = _pending_digest(queue)

    approved = OperatorApprovalConsole(queue).approve(digest, "alice")

    assert approved["status"] == "approved"
    assert approved["approver_digest"] == hashlib.sha256(b"alice").hexdigest()
    assert "alice" not in repr(approved)
    assert queue.request_approval(None, _request()) is True


def test_webhook_sink_posts_signed_redacted_event() -> None:
    opener = _CaptureOpener()
    event = ApprovalWebhookEvent(
        "director_class_ai.approval.approved",
        {"digest": "abc", "status": "approved", "approver_digest": "def"},
    )
    sink = ApprovalWebhookSink(
        "http://127.0.0.1/hooks",
        signing_key="fixture-key",
        timeout_seconds=2.0,
        opener=opener,
    )

    sink.publish(event)
    request = opener.requests[0]
    body = request.data or b""
    expected = hmac.new(b"fixture-key", body, hashlib.sha256).hexdigest()

    assert request.full_url == "http://127.0.0.1/hooks"
    assert opener.timeouts == [2.0]
    assert json.loads(body.decode("utf-8"))["ticket"]["digest"] == "abc"
    headers = {key.lower(): value for key, value in request.header_items()}
    assert headers[APPROVAL_SIGNATURE_HEADER.lower()] == expected


def test_webhook_sink_default_opener_posts_to_loopback() -> None:
    received: list[bytes] = []

    class _WebhookHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return None

        def do_POST(self) -> None:
            length = int(self.headers["content-length"])
            received.append(self.rfile.read(length))
            self.send_response(HTTPStatus.ACCEPTED)
            self.send_header("content-length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _WebhookHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sink = ApprovalWebhookSink(f"http://127.0.0.1:{server.server_port}/hook")

    try:
        sink.publish(
            ApprovalWebhookEvent(
                "director_class_ai.approval.denied",
                {"digest": "abc", "status": "denied"},
            )
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)

    assert json.loads(received[0].decode("utf-8"))["ticket"]["status"] == "denied"


def test_service_requires_operator_key() -> None:
    with pytest.raises(ValueError, match="operator_key is required"):
        ApprovalServiceConfig(operator_key="")


def test_service_pending_requires_matching_key(tmp_path: Path) -> None:
    queue = _queue(tmp_path / "approvals.json")
    _pending_digest(queue)
    service = ApprovalService(
        OperatorApprovalConsole(queue),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )

    response = service.handle("GET", "/v1/approvals/pending", operator_key="bad")

    assert response.status == HTTPStatus.UNAUTHORIZED
    assert response.body == {"error": "unauthorized"}


def test_service_health_does_not_require_operator_key(tmp_path: Path) -> None:
    service = ApprovalService(
        OperatorApprovalConsole(_queue(tmp_path / "approvals.json")),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )

    response = service.handle("GET", "/healthz")

    assert response.status == HTTPStatus.OK
    assert response.to_json() == b'{"status":"ok"}'


def test_service_method_and_body_errors(tmp_path: Path) -> None:
    service = ApprovalService(
        OperatorApprovalConsole(_queue(tmp_path / "approvals.json")),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )

    method = service.handle("GET", "/v1/approvals/unknown", operator_key="operator-key")
    missing = service.handle("POST", "/v1/approvals/approve", operator_key="operator-key")
    unknown = service.handle(
        "POST",
        "/v1/approvals/unknown",
        {},
        operator_key="operator-key",
    )

    assert method.status == HTTPStatus.METHOD_NOT_ALLOWED
    assert missing.status == HTTPStatus.BAD_REQUEST
    assert unknown.status == HTTPStatus.NOT_FOUND


def test_service_approves_pending_ticket_and_emits_webhook(
    tmp_path: Path,
) -> None:
    opener = _CaptureOpener()
    sink = ApprovalWebhookSink("http://127.0.0.1/hooks", opener=opener)
    queue = _queue(tmp_path / "approvals.json")
    digest = _pending_digest(queue)
    service = ApprovalService(
        OperatorApprovalConsole(queue, webhook_sink=sink),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )

    response = service.handle(
        "POST",
        "/v1/approvals/approve",
        {"digest": digest, "approver": "alice"},
        operator_key="operator-key",
    )

    assert response.status == HTTPStatus.OK
    assert response.body["ticket"]["status"] == "approved"
    assert opener.requests
    assert queue.request_approval(None, _request()) is True
    assert "alice" not in repr(response.body)
    assert "rm -rf" not in repr(response.body)


def test_service_denies_pending_ticket(tmp_path: Path) -> None:
    queue = _queue(tmp_path / "approvals.json")
    digest = _pending_digest(queue)
    service = ApprovalService(
        OperatorApprovalConsole(queue),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )

    response = service.handle(
        "POST",
        "/v1/approvals/deny",
        {"digest": digest, "approver": "alice"},
        operator_key="operator-key",
    )

    assert response.status == HTTPStatus.OK
    assert response.body["ticket"]["status"] == "denied"
    assert queue.request_approval(None, _request()) is False


def test_service_reports_missing_ticket(tmp_path: Path) -> None:
    service = ApprovalService(
        OperatorApprovalConsole(_queue(tmp_path / "approvals.json")),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )

    response = service.handle(
        "POST",
        "/v1/approvals/approve",
        {"digest": "missing", "approver": "alice"},
        operator_key="operator-key",
    )

    assert response.status == HTTPStatus.NOT_FOUND
    assert response.body == {"error": "ticket_not_found"}


def test_service_rejects_missing_fields(tmp_path: Path) -> None:
    service = ApprovalService(
        OperatorApprovalConsole(_queue(tmp_path / "approvals.json")),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )

    response = service.handle(
        "POST",
        "/v1/approvals/approve",
        {"digest": "abc"},
        operator_key="operator-key",
    )

    assert response.status == HTTPStatus.BAD_REQUEST
    assert response.body == {"error": "digest_and_approver_required"}


def test_service_conflicts_when_ticket_is_not_pending(tmp_path: Path) -> None:
    queue = _queue(tmp_path / "approvals.json")
    digest = _pending_digest(queue)
    console = OperatorApprovalConsole(queue)
    service = ApprovalService(
        console,
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )
    console.deny(digest, "alice")

    response = service.handle(
        "POST",
        "/v1/approvals/approve",
        {"digest": digest, "approver": "bob"},
        operator_key="operator-key",
    )

    assert response.status == HTTPStatus.CONFLICT
    assert response.body == {"error": "ticket_not_pending"}


def test_http_server_handles_pending_request(tmp_path: Path) -> None:
    queue = _queue(tmp_path / "approvals.json")
    _pending_digest(queue)
    service = ApprovalService(
        OperatorApprovalConsole(queue),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )
    server = OperatorApprovalHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/v1/approvals/pending"
    request = Request(url, headers={APPROVAL_AUTH_HEADER: "operator-key"})

    try:
        with urlopen(request, timeout=5.0) as response:
            body = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)

    assert body["tickets"][0]["status"] == "pending"
    assert "rm -rf" not in repr(body)


def test_http_server_handles_approve_request(tmp_path: Path) -> None:
    queue = _queue(tmp_path / "approvals.json")
    digest = _pending_digest(queue)
    service = ApprovalService(
        OperatorApprovalConsole(queue),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )
    server = OperatorApprovalHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/v1/approvals/approve"
    body = json.dumps({"digest": digest, "approver": "alice"}).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={
            APPROVAL_AUTH_HEADER: "operator-key",
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=5.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)

    assert payload["ticket"]["status"] == "approved"
    assert queue.request_approval(None, _request()) is True


def test_http_server_rejects_malformed_post_bodies(tmp_path: Path) -> None:
    service = ApprovalService(
        OperatorApprovalConsole(_queue(tmp_path / "approvals.json")),
        config=ApprovalServiceConfig(operator_key="operator-key", max_body_bytes=4),
    )
    server = OperatorApprovalHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5.0)

    try:
        conn.request(
            "POST",
            "/v1/approvals/approve",
            body=b"{}{}{}",
            headers={APPROVAL_AUTH_HEADER: "operator-key"},
        )
        too_large = conn.getresponse()
        too_large.read()
        conn.request(
            "POST",
            "/v1/approvals/approve",
            body=b"{",
            headers={APPROVAL_AUTH_HEADER: "operator-key"},
        )
        invalid = conn.getresponse()
        invalid.read()
        conn.request(
            "POST",
            "/v1/approvals/approve",
            body=b"[]",
            headers={APPROVAL_AUTH_HEADER: "operator-key"},
        )
        array_body = conn.getresponse()
        array_body.read()
    finally:
        conn.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)

    assert too_large.status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert invalid.status == HTTPStatus.BAD_REQUEST
    assert array_body.status == HTTPStatus.BAD_REQUEST


def test_content_length_parser_rejects_absent_invalid_and_negative() -> None:
    assert _content_length(None) is None
    assert _content_length("not-an-int") is None
    assert _content_length("-1") is None


def test_http_server_rejects_invalid_key(tmp_path: Path) -> None:
    service = ApprovalService(
        OperatorApprovalConsole(_queue(tmp_path / "approvals.json")),
        config=ApprovalServiceConfig(operator_key="operator-key"),
    )
    server = OperatorApprovalHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/v1/approvals/pending"

    try:
        with pytest.raises(HTTPError) as exc:
            urlopen(url, timeout=5.0)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)

    assert exc.value.code == HTTPStatus.UNAUTHORIZED


def test_webhook_sink_rejects_non_http_scheme() -> None:
    import pytest

    from director_class_ai.approvals.transport import ApprovalWebhookSink

    for bad in ("file:///etc/passwd", "ftp://host/p", "gopher://x"):
        with pytest.raises(ValueError, match="must be http or https"):
            ApprovalWebhookSink(bad)
