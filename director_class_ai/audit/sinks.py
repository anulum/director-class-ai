# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — SIEM-safe audit export sinks

"""SIEM-safe export views over the local tamper-evident audit chain.

The local hash chain remains the source of truth. Exporters first verify the
chain, then map each chain entry to a small event record containing the decision
id, detector ids, policy profile, approval state, request digest, and verdict
booleans. Raw prompts, actions, context, responses, and command output are never
included in the export schema.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..evidence.techniques import TechniqueTag, technique_tags_for_findings
from .chain import verify_chain

if TYPE_CHECKING:
    from ..core.governor import AuditRecord

__all__ = [
    "AUDIT_EVENT_NAME",
    "AuditExportEvent",
    "audit_record_to_event",
    "chain_entry_to_event",
    "export_chain_to_siem_jsonl",
]

AUDIT_EVENT_NAME = "director_class_ai.governance.decision"
_SCHEMA_VERSION = "director-class-ai.audit.v1"


@dataclass(frozen=True)
class AuditExportEvent:
    """A SIEM-safe governance event derived from a verified audit entry."""

    decision_id: str
    observed_at_unix: float
    policy_profile: str
    approval_state: str
    request_digest: str
    detector_ids: tuple[str, ...]
    risk: float
    permitted: bool
    escalated: bool
    requires_human: bool
    technique_ids: tuple[str, ...] = ()
    technique_tags: tuple[TechniqueTag, ...] = ()
    chain_sequence: int | None = None
    chain_entry_hash: str = ""

    def to_siem_json(self) -> dict[str, object]:
        """Return the stable JSON object for SIEM ingestion."""
        return {
            "schema_version": _SCHEMA_VERSION,
            "event_name": AUDIT_EVENT_NAME,
            "decision_id": self.decision_id,
            "observed_at_unix": self.observed_at_unix,
            "policy_profile": self.policy_profile,
            "approval_state": self.approval_state,
            "request_digest": self.request_digest,
            "detector_ids": list(self.detector_ids),
            "technique_ids": list(self.technique_ids),
            "technique_tags": [tag.to_json() for tag in self.technique_tags],
            "risk": self.risk,
            "permitted": self.permitted,
            "escalated": self.escalated,
            "requires_human": self.requires_human,
            "chain_sequence": self.chain_sequence,
            "chain_entry_hash": self.chain_entry_hash,
        }

    def to_otel_attributes(self) -> dict[str, object]:
        """Return OpenTelemetry-style event attributes."""
        return {
            "event.name": AUDIT_EVENT_NAME,
            "event.schema_url": _SCHEMA_VERSION,
            "decision.id": self.decision_id,
            "policy.profile": self.policy_profile,
            "approval.state": self.approval_state,
            "request.digest": self.request_digest,
            "detector.ids": list(self.detector_ids),
            "threat.technique.ids": list(self.technique_ids),
            "threat.technique.names": [tag.technique_name for tag in self.technique_tags],
            "governance.risk": self.risk,
            "governance.permitted": self.permitted,
            "governance.escalated": self.escalated,
            "governance.requires_human": self.requires_human,
            "audit.chain_sequence": self.chain_sequence,
            "audit.chain_entry_hash": self.chain_entry_hash,
        }


def audit_record_to_event(
    record: AuditRecord,
    *,
    policy_profile: str = "",
    observed_at_unix: float = 0.0,
    decision_id: str = "",
) -> AuditExportEvent:
    """Map a live Governor audit record to the export schema."""
    approval_state = _approval_state(record.permitted, record.escalated)
    stable_id = decision_id or _stable_decision_id(
        {
            "approval_state": approval_state,
            "request_digest": record.request_digest,
            "firing": list(record.firing),
            "risk": record.risk,
            "permitted": record.permitted,
            "escalated": record.escalated,
        }
    )
    technique_tags = technique_tags_for_findings(record.firing)
    return AuditExportEvent(
        decision_id=stable_id,
        observed_at_unix=observed_at_unix,
        policy_profile=policy_profile,
        approval_state=approval_state,
        request_digest=record.request_digest,
        detector_ids=tuple(record.firing),
        technique_ids=_technique_ids(technique_tags),
        technique_tags=technique_tags,
        risk=record.risk,
        permitted=record.permitted,
        escalated=record.escalated,
        requires_human=record.requires_human,
    )


def chain_entry_to_event(entry: dict[str, object]) -> AuditExportEvent:
    """Map one verified hash-chain entry to the export schema."""
    entry_hash = _string(entry.get("entry_hash"))
    detector_ids = tuple(_strings(entry.get("firing")))
    technique_tags = technique_tags_for_findings(detector_ids)
    return AuditExportEvent(
        decision_id=entry_hash,
        observed_at_unix=_float(entry.get("created_at")),
        policy_profile=_string(entry.get("policy_profile")),
        approval_state=_string(entry.get("approval_state")),
        request_digest=_string(entry.get("request_digest")),
        detector_ids=detector_ids,
        technique_ids=_technique_ids(technique_tags),
        technique_tags=technique_tags,
        risk=_float(entry.get("risk")),
        permitted=_bool(entry.get("permitted")),
        escalated=_bool(entry.get("escalated")),
        requires_human=_bool(entry.get("requires_human")),
        chain_sequence=_optional_int(entry.get("seq")),
        chain_entry_hash=entry_hash,
    )


def export_chain_to_siem_jsonl(
    path: str | Path,
    *,
    out_path: str | Path | None = None,
    head_signing_key: bytes | str | None = None,
    anchor_path: str | Path | None = None,
) -> str:
    """Verify a local audit chain, then export SIEM-safe JSONL events."""
    source = Path(path)
    verification = verify_chain(
        source,
        head_signing_key=head_signing_key,
        anchor_path=anchor_path,
    )
    if not verification.ok:
        raise ValueError(f"audit chain verification failed: {verification.reason}")

    lines = [
        json.dumps(chain_entry_to_event(entry).to_siem_json(), sort_keys=True)
        for entry in _read_entries(source)
    ]
    body = "\n".join(lines) + ("\n" if lines else "")
    if out_path is not None:
        Path(out_path).write_text(body, encoding="utf-8")
    return body


def _read_entries(path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        entries.append(cast(dict[str, object], raw))
    return entries


def _stable_decision_id(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _technique_ids(tags: tuple[TechniqueTag, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(tag.technique_id for tag in tags))


def _approval_state(permitted: bool, escalated: bool) -> str:
    if escalated:
        return "approved" if permitted else "denied_or_pending"
    return "permitted" if permitted else "blocked"


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _float(value: object) -> float:
    return float(value) if isinstance(value, int | float) else 0.0


def _bool(value: object) -> bool:
    return value if isinstance(value, bool) else False


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]
