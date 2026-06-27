# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — halt sidecar tests

from __future__ import annotations

import json
import threading
import tomllib
import urllib.error
import urllib.request
from contextlib import AbstractContextManager
from pathlib import Path

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


def _get(url: str, *, operator_key: str = "") -> dict[str, object]:
    headers = {HALT_AUTH_HEADER: operator_key} if operator_key else {}
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        loaded = json.loads(response.read().decode("utf-8"))
    assert isinstance(loaded, dict)
    return loaded
