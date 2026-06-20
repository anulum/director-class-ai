# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP gateway service entry point

"""Console entry point for the local MCP gateway service/proxy."""

from __future__ import annotations

import argparse
import ipaddress
import os
from collections.abc import Sequence
from dataclasses import dataclass

from .mcp_service import (
    MCPGatewayHTTPServer,
    MCPGatewayService,
    MCPGatewayServiceConfig,
)

__all__ = ["MCPGatewayServerOptions", "build_gateway_server", "main"]


@dataclass(frozen=True)
class MCPGatewayServerOptions:
    """Runtime options for the local MCP gateway service."""

    host: str = "127.0.0.1"
    port: int = 8765
    allow_dynamic_discovery: bool = False
    require_signed_registrations: bool = True
    max_body_bytes: int = 1_048_576
    operator_key: str = ""
    operator_key_env: str = ""

    @classmethod
    def from_argv(
        cls,
        argv: Sequence[str] | None = None,
    ) -> MCPGatewayServerOptions:
        """Parse command-line arguments into service options."""
        args = _parser().parse_args(argv)
        operator_key_env = str(args.operator_key_env or "").strip()
        return cls(
            host=args.host,
            port=args.port,
            allow_dynamic_discovery=args.allow_dynamic_discovery,
            require_signed_registrations=not args.allow_unsigned_registrations,
            max_body_bytes=args.max_body_bytes,
            operator_key=os.environ.get(operator_key_env, "") if operator_key_env else "",
            operator_key_env=operator_key_env,
        )


def build_gateway_server(options: MCPGatewayServerOptions) -> MCPGatewayHTTPServer:
    """Build a configured loopback MCP gateway HTTP server."""
    if not _is_loopback(options.host) and not options.operator_key:
        raise ValueError("non-loopback MCP gateway binding requires --operator-key-env")
    service = MCPGatewayService(
        config=MCPGatewayServiceConfig(
            allow_dynamic_discovery=options.allow_dynamic_discovery,
            require_signed_registrations=options.require_signed_registrations,
            max_body_bytes=options.max_body_bytes,
            operator_key=options.operator_key,
        )
    )
    return MCPGatewayHTTPServer((options.host, options.port), service)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the local MCP gateway service until interrupted."""
    options = MCPGatewayServerOptions.from_argv(argv)
    server = build_gateway_server(options)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="director-class-mcp-gateway",
        description="Run the local Director-Class AI MCP gateway service.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address. Default: 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Bind port. Default: 8765.",
    )
    parser.add_argument(
        "--allow-dynamic-discovery",
        action="store_true",
        help="Allow unknown tools to pass registry lookup after discovery review.",
    )
    parser.add_argument(
        "--allow-unsigned-registrations",
        action="store_true",
        help="Permit unsigned registry entries for local development.",
    )
    parser.add_argument(
        "--max-body-bytes",
        type=int,
        default=1_048_576,
        help="Maximum accepted JSON request body size. Default: 1048576.",
    )
    parser.add_argument(
        "--operator-key-env",
        default="",
        help=(
            "Environment variable containing the operator key required for MCP "
            "gateway requests. Required when binding outside loopback."
        ),
    )
    return parser


def _is_loopback(host: str) -> bool:
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
