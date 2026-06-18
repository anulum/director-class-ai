# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP gateway entry-point tests

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from director_class_ai.gateway import MCPGatewayServerOptions, build_gateway_server
from director_class_ai.gateway.mcp_cli import _is_loopback, main

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_gateway_server_options_parse_defaults() -> None:
    options = MCPGatewayServerOptions.from_argv(())

    assert options.host == "127.0.0.1"
    assert options.port == 8765
    assert options.allow_dynamic_discovery is False
    assert options.require_signed_registrations is True
    assert options.max_body_bytes == 1_048_576
    assert options.operator_key == ""
    assert options.operator_key_env == ""


def test_gateway_server_options_parse_runtime_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DIRECTOR_CLASS_MCP_KEY", "operator-key")

    options = MCPGatewayServerOptions.from_argv(
        (
            "--host",
            "127.0.0.2",
            "--port",
            "0",
            "--allow-dynamic-discovery",
            "--allow-unsigned-registrations",
            "--max-body-bytes",
            "4096",
            "--operator-key-env",
            "DIRECTOR_CLASS_MCP_KEY",
        )
    )

    assert options.host == "127.0.0.2"
    assert options.port == 0
    assert options.allow_dynamic_discovery is True
    assert options.require_signed_registrations is False
    assert options.max_body_bytes == 4096
    assert options.operator_key == "operator-key"
    assert options.operator_key_env == "DIRECTOR_CLASS_MCP_KEY"


def test_build_gateway_server_binds_loopback_and_serves_health() -> None:
    server = build_gateway_server(MCPGatewayServerOptions(port=0))
    try:
        response = server.service.handle("GET", "/healthz")

        assert server.server_address[0] == "127.0.0.1"
        assert server.server_address[1] > 0
        assert response.status == 200
        assert response.body == {"status": "ok", "registration_count": 0}
    finally:
        server.server_close()


def test_build_gateway_server_rejects_non_loopback_without_operator_key() -> None:
    with pytest.raises(ValueError, match="operator-key-env"):
        build_gateway_server(MCPGatewayServerOptions(host="0.0.0.0", port=0))


def test_build_gateway_server_allows_non_loopback_with_operator_key() -> None:
    server = build_gateway_server(
        MCPGatewayServerOptions(
            host="0.0.0.0",
            port=0,
            operator_key="operator-key",
        )
    )
    try:
        response = server.service.handle("GET", "/healthz")

        assert server.server_address[1] > 0
        assert response.status == 200
    finally:
        server.server_close()


def test_loopback_host_classifier_covers_named_ip_and_invalid_hosts() -> None:
    assert _is_loopback("localhost") is True
    assert _is_loopback("") is True
    assert _is_loopback("127.0.0.1") is True
    assert _is_loopback("::1") is True
    assert _is_loopback("0.0.0.0") is False
    assert _is_loopback("gateway.internal") is False


def test_gateway_console_script_is_declared() -> None:
    with _PYPROJECT.open("rb") as handle:
        project = tomllib.load(handle)["project"]

    assert project["scripts"]["director-class-mcp-gateway"] == (
        "director_class_ai.gateway.mcp_cli:main"
    )


def test_main_closes_server_on_keyboard_interrupt(monkeypatch) -> None:
    closed: list[bool] = []

    class _Server:
        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(
        "director_class_ai.gateway.mcp_cli.build_gateway_server",
        lambda _options: _Server(),
    )

    assert main(("--port", "0")) == 130
    assert closed == [True]


def test_main_closes_server_after_clean_shutdown(monkeypatch) -> None:
    closed: list[bool] = []

    class _Server:
        def serve_forever(self) -> None:
            return None

        def server_close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(
        "director_class_ai.gateway.mcp_cli.build_gateway_server",
        lambda _options: _Server(),
    )

    assert main(("--port", "0")) == 0
    assert closed == [True]
