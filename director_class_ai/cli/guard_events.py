# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — command guard event helpers

"""Privacy-preserving event helpers for the command guard CLI."""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..audit import AuditChainSink
from ..core.governor import AuditRecord, digest_request
from ..policy import RuntimePostureResolution
from ..sdk import ToolReviewRequest

__all__ = ["runtime_posture_block_event"]


def runtime_posture_block_event(
    *,
    surface: str,
    execute: bool,
    audit_log: str,
    approval_store: str,
    request: ToolReviewRequest,
    posture: RuntimePostureResolution,
) -> dict[str, object]:
    """Return and audit a fail-closed runtime-posture block."""
    evaluation = request.to_evaluation()
    request_digest = digest_request(evaluation)
    action_digest = hashlib.sha256(request.rendered_action().encode("utf-8")).hexdigest()[
        :16
    ]
    record = AuditRecord(
        permitted=False,
        escalated=False,
        risk=1.0,
        requires_human=False,
        rationale=posture.rationale,
        firing=(posture.blocking_signal,),
        request_digest=request_digest,
    )
    AuditChainSink(Path(audit_log))(record)
    event: dict[str, object] = {
        "event_type": "tool_middleware_decision",
        "tool_name": request.tool_name,
        "route": "block",
        "permitted": False,
        "escalated": False,
        "executed": False,
        "risk": 1.0,
        "requires_human": False,
        "firing": record.firing,
        "request_digest": request_digest,
        "action_digest": action_digest,
        "argument_keys": tuple(sorted(request.arguments)),
        "argument_count": len(request.arguments),
        "tainted_argument_keys": request.tainted_argument_keys(),
        "metadata_keys": tuple(sorted(request.metadata)),
        "output_digest": "",
        "output_size": 0,
        "exit_code": None,
        "surface": surface,
        "dry_run": not execute,
        "audit_log": audit_log,
        "approval_store": approval_store,
    }
    if posture.drift_event is not None:
        event["policy_drift"] = {
            "approved_digest": posture.drift_event.approved_digest,
            "live_digest": posture.drift_event.live_digest,
            "changes": tuple(change.field for change in posture.drift_event.changes),
            "detected_at": posture.drift_event.detected_at,
        }
    return event
