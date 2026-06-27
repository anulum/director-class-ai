# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — halt sidecar tests

from __future__ import annotations

import http.client
import json
import threading
import tomllib
import urllib.error
import urllib.request
from contextlib import AbstractContextManager
from pathlib import Path

import pytest

import director_class_ai.sidecar.cli as halt_cli
from director_class_ai.sidecar.cli import HaltSidecarOptions, run_sidecar_command
from director_class_ai.sidecar.service import (
    HALT_AUTH_HEADER,
    HaltSwitchHTTPServer,
    HaltSwitchService,
    HaltSwitchServiceConfig,
)
from director_class_ai.sidecar.state import HaltSwitchSnapshot, LocalHaltSwitch

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_local_halt_switch_persists_generation_and_state(tmp_path: Path) -> None:
    switch = LocalHaltSwitch(tmp_path / "halt.json")

    initial = switch.snapshot()
    halted = switch.halt(
        reason="compromised agent",
        actor="operator-a",
        updated_at="2026-06-27T00:00:00Z",
    )
    resumed = LocalHaltSwitch(tmp_path / "halt.json").resume(
        reason="incident closed",
        actor="operator-b",
        updated_at="2026-06-27T00:01:00Z",
    )

    assert initial == HaltSwitchSnapshot.inactive()
    assert halted.halted is True
    assert halted.generation == 1
    assert resumed.halted is False
    assert resumed.generation == 2
    assert LocalHaltSwitch(tmp_path / "halt.json").snapshot() == resumed


def test_local_halt_switch_rejects_invalid_operator_changes(tmp_path: Path) -> None:
    switch = LocalHaltSwitch(tmp_path / "halt.json")

    for method in (switch.halt, switch.resume):
        try:
            method(reason="", actor="operator-a")
        except ValueError as exc:
            assert "reason is required" in str(exc)
        else:
            raise AssertionError("empty reason unexpectedly succeeded")

        try:
            method(reason="incident", actor="")
        except ValueError as exc:
            assert "actor is required" in str(exc)
        else:
            raise AssertionError("empty actor unexpectedly succeeded")


def test_service_protects_halt_and_resume_with_operator_key(tmp_path: Path) -> None:
    service = HaltSwitchService(
        LocalHaltSwitch(tmp_path / "halt.json"),
        config=HaltSwitchServiceConfig(operator_key="operator-key"),
    )

    health = service.handle("GET", "/healthz")
    missing = service.handle("POST", "/v1/halt", {})
    halted = service.handle(
        "POST",
        "/v1/halt",
        {"reason": "kill switch", "actor": "alice"},
        operator_key="operator-key",
    )
    status = service.handle("GET", "/v1/halt", operator_key="operator-key")
    resumed = service.handle(
        "POST",
        "/v1/resume",
        {"reason": "reviewed", "actor": "bob"},
        operator_key="operator-key",
    )

    assert health.body == {"status": "ok"}
    assert missing.status == 401
    assert halted.status == 200
    assert halted.body["halted"] is True
    assert status.body["generation"] == 1
    assert resumed.body["halted"] is False
    assert resumed.body["generation"] == 2


def test_loopback_halt_sidecar_handles_real_http_requests(tmp_path: Path) -> None:
    service = HaltSwitchService(
        LocalHaltSwitch(tmp_path / "halt.json"),
        config=HaltSwitchServiceConfig(operator_key="operator-key"),
    )

    with _running_server(service) as base_url:
        unauth_status, unauth_body = _post_error(
            f"{base_url}/v1/halt",
            {"reason": "incident", "actor": "alice"},
        )
        halted = _post(
            f"{base_url}/v1/halt",
            {"reason": "incident", "actor": "alice"},
            operator_key="operator-key",
        )
        status = _get(f"{base_url}/v1/halt", operator_key="operator-key")

    assert unauth_status == 401
    assert unauth_body == {"error": "unauthorized"}
    assert halted["halted"] is True
    assert status["reason"] == "incident"


def test_cli_commands_operate_the_same_state_file(tmp_path: Path) -> None:
    state_path = str(tmp_path / "halt.json")

    halted = run_sidecar_command(
        HaltSidecarOptions(
            command="halt",
            state_path=state_path,
            reason="incident",
            actor="alice",
        )
    )
    status = run_sidecar_command(
        HaltSidecarOptions(command="status", state_path=state_path)
    )
    resumed = run_sidecar_command(
        HaltSidecarOptions(
            command="resume",
            state_path=state_path,
            reason="closed",
            actor="bob",
        )
    )

    assert halted["halted"] is True
    assert status["halted"] is True
    assert resumed["halted"] is False


def test_cli_options_parse_and_main_writes_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_path = str(tmp_path / "halt.json")

    options = HaltSidecarOptions.from_argv(
        (
            "status",
            "--state-path",
            state_path,
            "--reason",
            "ignored",
            "--actor",
            "alice",
            "--host",
            "127.0.0.1",
            "--port",
            "8767",
            "--operator-key-env",
            "DCA_HALT_KEY",
        )
    )
    code = halt_cli.main(("status", "--state-path", state_path))
    captured = capsys.readouterr()

    assert options.command == "status"
    assert options.port == 8767
    assert options.operator_key_env == "DCA_HALT_KEY"
    assert code == 0
    assert json.loads(captured.out)["halted"] is False


def test_cli_serve_wires_operator_key_and_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    served: dict[str, object] = {}

    class _Server:
        def __init__(self, address: tuple[str, int], service: HaltSwitchService) -> None:
            served["address"] = address
            served["service"] = service

        def __enter__(self) -> _Server:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

        def serve_forever(self) -> None:
            served["called"] = True

    monkeypatch.setenv("DCA_HALT_KEY", "operator-key")
    monkeypatch.setattr(halt_cli, "HaltSwitchHTTPServer", _Server)

    code = halt_cli.main(
        (
            "serve",
            "--state-path",
            str(tmp_path / "halt.json"),
            "--operator-key-env",
            "DCA_HALT_KEY",
        )
    )

    assert code == 0
    assert served["address"] == ("127.0.0.1", 8766)
    assert served["called"] is True
    service = served["service"]
    assert isinstance(service, HaltSwitchService)
    assert service.config.operator_key == "operator-key"


def test_cli_rejects_unknown_non_serving_command(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsupported command"):
        run_sidecar_command(
            HaltSidecarOptions(command="unknown", state_path=str(tmp_path / "halt.json"))
        )


def test_service_rejects_empty_operator_key() -> None:
    with pytest.raises(ValueError, match="operator_key"):
        HaltSwitchServiceConfig(operator_key="")


def test_service_dispatch_error_paths(tmp_path: Path) -> None:
    service = HaltSwitchService(
        LocalHaltSwitch(tmp_path / "halt.json"),
        config=HaltSwitchServiceConfig(operator_key="operator-key"),
    )

    method = service.handle("PUT", "/v1/halt", operator_key="operator-key")
    missing = service.handle("POST", "/v1/halt", operator_key="operator-key")
    unknown = service.handle("POST", "/v1/unknown", {}, operator_key="operator-key")
    invalid = service.handle(
        "POST",
        "/v1/halt",
        {"reason": "", "actor": "alice"},
        operator_key="operator-key",
    )

    assert method.status == 405
    assert missing.status == 400
    assert unknown.status == 404
    assert invalid.status == 400


def test_loopback_sidecar_rejects_malformed_http_requests(tmp_path: Path) -> None:
    service = HaltSwitchService(
        LocalHaltSwitch(tmp_path / "halt.json"),
        config=HaltSwitchServiceConfig(operator_key="operator-key", max_body_bytes=8),
    )

    with _running_server(service) as base_url:
        host, port = base_url.removeprefix("http://").split(":")
        too_large = _raw_post_error(
            host,
            int(port),
            b'{"reason":"incident"}',
            operator_key="operator-key",
        )
        invalid_json = _raw_post_error(
            host,
            int(port),
            b"{bad",
            operator_key="operator-key",
        )
        non_object = _raw_post_error(
            host,
            int(port),
            b"[]",
            operator_key="operator-key",
        )

    assert too_large[0] == 413
    assert too_large[1] == {"error": "body_too_large"}
    assert invalid_json[0] == 400
    assert invalid_json[1] == {"error": "invalid_json"}
    assert non_object[0] == 400
    assert non_object[1] == {"error": "json_body_must_be_object"}


def test_content_length_parser_handles_bad_values() -> None:
    from director_class_ai.sidecar.service import _content_length

    assert _content_length(None) is None
    assert _content_length("bad") is None
    assert _content_length("-1") is None
    assert _content_length("0") == 0


def test_halt_state_rejects_corrupt_payloads() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        HaltSwitchSnapshot.from_json_dict([])
    with pytest.raises(ValueError, match="unsupported"):
        HaltSwitchSnapshot.from_json_dict({"schema_version": "old"})
    with pytest.raises(ValueError, match="generation"):
        HaltSwitchSnapshot.from_json_dict(
            {"schema_version": "director-class-ai.halt-state.v1", "generation": -1}
        )
    snapshot = HaltSwitchSnapshot.from_json_dict(
        {
            "schema_version": "director-class-ai.halt-state.v1",
            "halted": True,
            "reason": 7,
            "actor": ["alice"],
            "updated_at": None,
        }
    )
    assert snapshot.reason == ""
    assert snapshot.actor == ""
    assert snapshot.updated_at == ""


def test_halt_sidecar_console_script_is_declared() -> None:
    pyproject = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["director-class-halt-sidecar"] == (
        "director_class_ai.sidecar.cli:main"
    )


class _running_server(AbstractContextManager[str]):
    def __init__(self, service: HaltSwitchService) -> None:
        self._server = HaltSwitchHTTPServer(("127.0.0.1", 0), service)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
        )

    def __enter__(self) -> str:
        self._thread.start()
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _post(
    url: str,
    payload: dict[str, object],
    *,
    operator_key: str = "",
) -> dict[str, object]:
    headers = {"content-type": "application/json"}
    if operator_key:
        headers[HALT_AUTH_HEADER] = operator_key
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        loaded = json.loads(response.read().decode("utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _post_error(
    url: str,
    payload: dict[str, object],
) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"content-type": "application/json"},
    )
    try:
        urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        loaded = json.loads(exc.read().decode("utf-8"))
        assert isinstance(loaded, dict)
        return exc.code, loaded
    raise AssertionError("request unexpectedly succeeded")


def _raw_post_error(
    host: str,
    port: int,
    body: bytes,
    *,
    operator_key: str,
) -> tuple[int, dict[str, object]]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.request(
            "POST",
            "/v1/halt",
            body=body,
            headers={
                "content-type": "application/json",
                HALT_AUTH_HEADER: operator_key,
            },
        )
        response = connection.getresponse()
        loaded = json.loads(response.read().decode("utf-8"))
        assert isinstance(loaded, dict)
        return response.status, loaded
    finally:
        connection.close()


def _get(url: str, *, operator_key: str = "") -> dict[str, object]:
    headers = {HALT_AUTH_HEADER: operator_key} if operator_key else {}
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        loaded = json.loads(response.read().decode("utf-8"))
    assert isinstance(loaded, dict)
    return loaded
