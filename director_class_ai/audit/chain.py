# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — tamper-evident hash-chained audit log

"""A durable, tamper-evident audit trail for governance decisions.

The Governor's in-memory trail does not survive a restart and cannot prove its
own integrity — unacceptable for a regulated or mission-critical buyer. This sink
appends each decision as one JSON line whose ``entry_hash`` covers the previous
entry's hash, so any mutation, reordering, or deletion breaks the chain and is
located by :func:`verify_chain`. A small ``.head`` sidecar records the latest
``(seq, entry_hash)`` so even truncation of the tail — which a bare chain cannot
see, a valid prefix being indistinguishable from the whole — is caught.

It is wired through the Governor's existing ``audit_sink`` seam; raw prompt/action
text never enters the log (only the request digest, the verdict, and which
detectors fired), so the trail is safe to retain.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.governor import AuditRecord

__all__ = ["AuditChainSink", "ChainVerification", "verify_chain"]

_GENESIS = "0" * 64


def _approval_state(permitted: bool, escalated: bool) -> str:
    if escalated:
        return "approved" if permitted else "denied_or_pending"
    return "permitted" if permitted else "blocked"


def _entry_hash(prev_hash: str, payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


@dataclass
class AuditChainSink:
    """Append governance decisions to a tamper-evident hash-chained JSONL log."""

    path: Path
    policy_profile: str = ""
    clock: Callable[[], float] = time.time

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self._lock = threading.Lock()
        self._head_path = self.path.with_suffix(self.path.suffix + ".head")

    def _last(self) -> tuple[int, str]:
        if not self.path.exists():
            return -1, _GENESIS
        last_line = ""
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last_line = line
        if not last_line:
            return -1, _GENESIS
        rec = json.loads(last_line)
        return int(rec["seq"]), str(rec["entry_hash"])

    def __call__(self, record: AuditRecord) -> None:
        with self._lock:
            seq, prev_hash = self._last()
            seq += 1
            payload: dict[str, object] = {
                "seq": seq,
                "prev_hash": prev_hash,
                "created_at": self.clock(),
                "policy_profile": self.policy_profile,
                "permitted": record.permitted,
                "escalated": record.escalated,
                "approval_state": _approval_state(record.permitted, record.escalated),
                "risk": record.risk,
                "requires_human": record.requires_human,
                "rationale": record.rationale,
                "firing": list(record.firing),
                "request_digest": record.request_digest,
            }
            entry = dict(payload)
            entry["entry_hash"] = _entry_hash(prev_hash, payload)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
            self._head_path.write_text(
                json.dumps({"seq": seq, "entry_hash": entry["entry_hash"]}),
                encoding="utf-8",
            )


@dataclass(frozen=True)
class ChainVerification:
    """Result of verifying an audit chain."""

    ok: bool
    first_bad_index: int | None = None
    reason: str = ""


def verify_chain(path: str | Path) -> ChainVerification:
    """Recompute the chain and report the first broken link, if any."""
    path = Path(path)
    if not path.exists():
        return ChainVerification(False, None, "audit log does not exist")
    prev_hash = _GENESIS
    expected_seq = 0
    last_hash = _GENESIS
    last_seq = -1
    with path.open(encoding="utf-8") as fh:
        for index, line in enumerate(fh):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return ChainVerification(False, index, "corrupt / truncated JSON line")
            stored = entry.pop("entry_hash", None)
            if entry.get("seq") != expected_seq:
                return ChainVerification(False, index, "sequence number out of order")
            if entry.get("prev_hash") != prev_hash:
                return ChainVerification(False, index, "prev_hash does not chain")
            recomputed = _entry_hash(prev_hash, entry)
            if recomputed != stored:
                return ChainVerification(False, index, "entry_hash mismatch (mutated)")
            prev_hash = recomputed
            last_hash = recomputed
            last_seq = expected_seq
            expected_seq += 1

    head_path = path.with_suffix(path.suffix + ".head")
    if head_path.exists():
        head = json.loads(head_path.read_text(encoding="utf-8"))
        if head.get("seq") != last_seq or head.get("entry_hash") != last_hash:
            return ChainVerification(
                False, last_seq, "head sidecar mismatch (tail truncated)"
            )
    return ChainVerification(True)
