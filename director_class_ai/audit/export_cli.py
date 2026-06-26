# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — verified audit export CLI

"""Console packaging for verified SIEM/SOC audit exports.

The command-line surface is intentionally thin: it delegates schema construction
to :mod:`director_class_ai.audit.sinks`, verifies the local hash chain before any
write, and returns a nonzero process code when the chain is missing or tampered.
This lets operators schedule exports from the same package without giving the
exporter access to raw prompts, actions, responses, or command output.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .sinks import export_chain_to_siem_jsonl

__all__ = ["AuditExportOptions", "AuditExportResult", "main", "run_export"]


@dataclass(frozen=True)
class AuditExportOptions:
    """Runtime options for exporting a verified audit chain."""

    source: Path
    output: Path | None = None
    head_signing_key: str | None = None
    head_signing_key_env: str = ""
    anchor_path: Path | None = None

    @classmethod
    def from_argv(cls, argv: Sequence[str] | None = None) -> AuditExportOptions:
        """Parse command-line arguments into audit-export options."""
        args = _parser().parse_args(argv)
        output = Path(args.output) if args.output else None
        anchor_path = Path(args.anchor_log) if args.anchor_log else None
        return cls(
            source=Path(args.source),
            output=output,
            head_signing_key_env=args.head_signing_key_env,
            anchor_path=anchor_path,
        )


@dataclass(frozen=True)
class AuditExportResult:
    """Outcome of one verified SIEM/SOC audit export."""

    ok: bool
    event_count: int
    source: Path
    output: Path | None = None
    reason: str = ""
    body: str = ""


def run_export(options: AuditExportOptions) -> AuditExportResult:
    """Verify and export an audit chain using fail-closed semantics."""
    try:
        body = export_chain_to_siem_jsonl(
            options.source,
            out_path=options.output,
            head_signing_key=_audit_head_key(options),
            anchor_path=options.anchor_path,
        )
    except ValueError as exc:
        return AuditExportResult(
            ok=False,
            event_count=0,
            source=options.source,
            output=options.output,
            reason=str(exc),
        )
    return AuditExportResult(
        ok=True,
        event_count=len(body.splitlines()),
        source=options.source,
        output=options.output,
        body=body,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the SIEM/SOC export command."""
    options = AuditExportOptions.from_argv(argv)
    result = run_export(options)
    if not result.ok:
        sys.stderr.write(result.reason + "\n")
        return 2
    if result.output is None:
        sys.stdout.write(result.body)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="director-class-siem-export",
        description="Verify a hash-chained audit log and export SIEM/SOC JSONL.",
    )
    parser.add_argument(
        "source",
        help="Hash-chained audit JSONL file produced by AuditChainSink.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="",
        help="Destination SIEM/SOC JSONL path. Omit to write JSONL to stdout.",
    )
    parser.add_argument(
        "--head-signing-key-env",
        default="",
        help="Environment variable containing the HMAC key for verifying the audit head.",
    )
    parser.add_argument(
        "--anchor-log",
        default="",
        help="Optional external anchor JSONL whose latest signed head must match.",
    )
    return parser


def _audit_head_key(options: AuditExportOptions) -> str | None:
    if options.head_signing_key is not None:
        return options.head_signing_key
    if not options.head_signing_key_env:
        return None
    value = os.environ.get(options.head_signing_key_env)
    if not value:
        raise ValueError(
            "audit head signing key environment variable "
            f"{options.head_signing_key_env!r} is not set"
        )
    return value


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
