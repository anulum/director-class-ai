# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — halt sidecar CLI

"""Command-line entry point for the operator-owned halt sidecar."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from .service import HaltSwitchHTTPServer, HaltSwitchService, HaltSwitchServiceConfig
from .state import HaltSwitchSnapshot, LocalHaltSwitch

__all__ = ["HaltSidecarOptions", "main", "run_sidecar_command"]

DEFAULT_HALT_STATE = "runtime/halt_state.json"


@dataclass(frozen=True)
class HaltSidecarOptions:
    """Parsed operator options for halt-switch commands."""

    command: str
    state_path: str = DEFAULT_HALT_STATE
    reason: str = ""
    actor: str = ""
    host: str = "127.0.0.1"
    port: int = 8766
    operator_key_env: str = "DIRECTOR_CLASS_HALT_KEY"

    @classmethod
    def from_argv(cls, argv: Sequence[str] | None = None) -> HaltSidecarOptions:
        """Parse CLI arguments into halt-sidecar options."""
        args = _parser().parse_args(argv)
        return cls(
            command=args.command,
            state_path=args.state_path,
            reason=args.reason,
            actor=args.actor,
            host=args.host,
            port=args.port,
            operator_key_env=args.operator_key_env,
        )


def run_sidecar_command(options: HaltSidecarOptions) -> dict[str, object]:
    """Execute one non-serving sidecar command and return JSON-ready status."""
    switch = LocalHaltSwitch(options.state_path)
    if options.command == "status":
        return _snapshot_event(switch.snapshot())
    if options.command == "halt":
        return _snapshot_event(switch.halt(reason=options.reason, actor=options.actor))
    if options.command == "resume":
        return _snapshot_event(switch.resume(reason=options.reason, actor=options.actor))
    raise ValueError(f"unsupported command {options.command!r}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the halt-sidecar CLI."""
    options = HaltSidecarOptions.from_argv(argv)
    if options.command == "serve":
        key = os.environ.get(options.operator_key_env, "")
        service = HaltSwitchService(
            LocalHaltSwitch(options.state_path),
            config=HaltSwitchServiceConfig(operator_key=key),
        )
        with HaltSwitchHTTPServer((options.host, options.port), service) as server:
            server.serve_forever()
        return 0
    event = run_sidecar_command(options)
    sys.stdout.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


def _snapshot_event(snapshot: HaltSwitchSnapshot) -> dict[str, object]:
    data = snapshot.to_json_dict()
    data.pop("schema_version", None)
    return data


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="director-class-halt-sidecar",
        description="Operate the durable out-of-band halt switch.",
    )
    parser.add_argument("command", choices=("status", "halt", "resume", "serve"))
    parser.add_argument(
        "--state-path",
        default=DEFAULT_HALT_STATE,
        help=f"Durable halt-state JSON path. Default: {DEFAULT_HALT_STATE}.",
    )
    parser.add_argument("--reason", default="", help="Operator reason for halt/resume.")
    parser.add_argument("--actor", default="", help="Operator identity.")
    parser.add_argument("--host", default="127.0.0.1", help="Serve host.")
    parser.add_argument("--port", type=int, default=8766, help="Serve port.")
    parser.add_argument(
        "--operator-key-env",
        default="DIRECTOR_CLASS_HALT_KEY",
        help="Environment variable containing the sidecar operator key.",
    )
    return parser
