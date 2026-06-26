# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — tamper-evident hash-chained audit log

"""A durable, tamper-evident audit trail for governance decisions.

The Governor's in-memory trail does not survive a restart. This sink appends
each decision as one JSON line whose ``entry_hash`` covers the previous entry's
hash, so any mutation, reordering, or deletion breaks the chain and is located by
:func:`verify_chain`. A small ``.head`` sidecar records the latest ``(seq,
entry_hash)`` so even truncation of the tail — which a bare chain cannot see, a
valid prefix being indistinguishable from the whole — is caught. The record is
tamper-evident against that trusted recorded head, not a legal or independently
anchored integrity claim.

It is wired through the Governor's existing ``audit_sink`` seam; raw prompt/action
text never enters the log (only the request digest, the verdict, and which
detectors fired), so the trail is safe to retain.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TypeAlias

from ..core.durability import atomic_write_text, durable_append_line

if TYPE_CHECKING:
    from ..core.governor import AuditRecord

__all__ = ["AuditChainSink", "ChainVerification", "verify_chain"]

_GENESIS = "0" * 64
_HeadSigningKey: TypeAlias = bytes | str
_RustEntryHash: TypeAlias = Callable[[str, str], str]
_RustVerifyChain: TypeAlias = Callable[
    [Sequence[str], str | None], tuple[bool, int | None, str]
]


def _approval_state(permitted: bool, escalated: bool) -> str:
    if escalated:
        return "approved" if permitted else "denied_or_pending"
    return "permitted" if permitted else "blocked"


def _load_rust_entry_hash() -> _RustEntryHash | None:
    try:
        module = importlib.import_module("director_class_ai._rust")
    except ImportError:
        return None
    entry_hash = getattr(module, "audit_entry_hash", None)
    return entry_hash if callable(entry_hash) else None


def _load_rust_verify_chain() -> _RustVerifyChain | None:
    try:
        module = importlib.import_module("director_class_ai._rust")
    except ImportError:
        return None
    verify = getattr(module, "audit_verify_chain", None)
    return verify if callable(verify) else None


_RUST_ENTRY_HASH = _load_rust_entry_hash()
_RUST_VERIFY_CHAIN = _load_rust_verify_chain()


def _entry_hash_python(prev_hash: str, payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _entry_hash(prev_hash: str, payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    python_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
    if _RUST_ENTRY_HASH is None:
        return python_hash
    try:
        rust_hash = _RUST_ENTRY_HASH(prev_hash, canonical)
    except Exception:
        return python_hash
    return rust_hash if rust_hash == python_hash else python_hash


def _head_payload(seq: int, entry_hash: object) -> dict[str, object]:
    return {"seq": seq, "entry_hash": entry_hash}


def _canonical_json(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _key_bytes(key: _HeadSigningKey) -> bytes:
    return key if isinstance(key, bytes) else key.encode("utf-8")


def _head_signature(head_json: str, key: _HeadSigningKey) -> str:
    return hmac.new(
        _key_bytes(key), head_json.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def _signature_payload(signature: str) -> dict[str, str]:
    return {"alg": "HMAC-SHA256", "signature": signature}


@dataclass
class AuditChainSink:
    """Append governance decisions to a tamper-evident hash-chained JSONL log.

    Parameters
    ----------
    path:
        Audit JSONL path.
    policy_profile:
        Runtime policy profile label copied into each audit record.
    clock:
        Time source used for deterministic tests and runtime timestamps.
    head_signing_key:
        Optional HMAC key for signing the head sidecar. Deployments that pass a
        key can detect an attacker who rewrites the log and head to an older
        valid prefix without also knowing the key.
    anchor_path:
        Optional append-only external anchor log for signed heads. The verifier
        can require its latest anchor to match the local signed head, detecting
        replay of an older signed prefix.
    """

    path: Path
    policy_profile: str = ""
    clock: Callable[[], float] = time.time
    head_signing_key: _HeadSigningKey | None = None
    anchor_path: Path | None = None

    def __post_init__(self) -> None:
        """Resolve sink paths and initialise the append lock."""
        self.path = Path(self.path)
        self._lock = threading.Lock()
        self._head_path = self.path.with_suffix(self.path.suffix + ".head")
        self._head_signature_path = self.path.with_suffix(self.path.suffix + ".head.sig")
        if self.anchor_path is not None:
            if self.head_signing_key is None:
                raise ValueError("anchor_path requires head_signing_key")
            self.anchor_path = Path(self.anchor_path)

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
        """Append one audit record while preserving chain continuity."""
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
            # fsync the entry to disk before the head advances, so a crash can
            # never leave a head that points past a record the chain has lost.
            durable_append_line(self.path, json.dumps(entry) + "\n")
            head_json = _canonical_json(_head_payload(seq, entry["entry_hash"]))
            atomic_write_text(
                self._head_path,
                head_json,
            )
            if self.head_signing_key is not None:
                signature = _head_signature(head_json, self.head_signing_key)
                atomic_write_text(
                    self._head_signature_path,
                    _canonical_json(_signature_payload(signature)),
                )
                if self.anchor_path is not None:
                    durable_append_line(
                        self.anchor_path,
                        _canonical_json(
                            {
                                "alg": "HMAC-SHA256",
                                "head": json.loads(head_json),
                                "signature": signature,
                            }
                        )
                        + "\n",
                    )


@dataclass(frozen=True)
class ChainVerification:
    """Result of verifying an audit chain."""

    ok: bool
    first_bad_index: int | None = None
    reason: str = ""


def verify_chain(
    path: str | Path,
    *,
    head_signing_key: _HeadSigningKey | None = None,
    anchor_path: str | Path | None = None,
) -> ChainVerification:
    """Recompute the chain and report the first broken link, if any.

    Parameters
    ----------
    path:
        Audit JSONL path.
    head_signing_key:
        Optional HMAC key required to verify the `.head.sig` sidecar.
    anchor_path:
        Optional external anchor log whose latest signed head must match the
        local signed head. Requires ``head_signing_key``.

    Returns
    -------
    ChainVerification
        Verification outcome. Signed verification is fail-closed: missing or
        mismatched signatures and anchors return ``ok=False``.
    """
    path = Path(path)
    if not path.exists():
        return ChainVerification(False, None, "audit log does not exist")
    python_result = _verify_chain_python(path)
    if not python_result.ok:
        return python_result
    signed_result = _verify_signed_head(path, head_signing_key, anchor_path)
    if not signed_result.ok:
        return signed_result
    if _RUST_VERIFY_CHAIN is None:
        return python_result
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        head_path = path.with_suffix(path.suffix + ".head")
        head_json = head_path.read_text(encoding="utf-8") if head_path.exists() else None
        rust_result = ChainVerification(*_RUST_VERIFY_CHAIN(lines, head_json))
    except Exception:
        return python_result
    return rust_result if rust_result == python_result else python_result


def _verify_signed_head(
    path: Path,
    head_signing_key: _HeadSigningKey | None,
    anchor_path: str | Path | None,
) -> ChainVerification:
    if anchor_path is not None and head_signing_key is None:
        return ChainVerification(
            False, None, "anchor verification requires head signature"
        )
    if head_signing_key is None:
        return ChainVerification(True)
    head_path = path.with_suffix(path.suffix + ".head")
    signature_path = path.with_suffix(path.suffix + ".head.sig")
    if not head_path.exists():
        return ChainVerification(False, None, "signed verification requires head sidecar")
    if not signature_path.exists():
        return ChainVerification(False, None, "head signature sidecar missing")
    try:
        head = json.loads(head_path.read_text(encoding="utf-8"))
        signature_payload = json.loads(signature_path.read_text(encoding="utf-8"))
        if not isinstance(head, dict) or not isinstance(signature_payload, dict):
            return ChainVerification(False, None, "head signature metadata is corrupt")
        head_json = _canonical_json(
            _head_payload(int(head["seq"]), str(head["entry_hash"]))
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return ChainVerification(False, None, "head signature metadata is corrupt")
    signature = str(signature_payload.get("signature", ""))
    expected = _head_signature(head_json, head_signing_key)
    if signature_payload.get("alg") != "HMAC-SHA256":
        return ChainVerification(False, None, "head signature algorithm mismatch")
    if not hmac.compare_digest(signature, expected):
        return ChainVerification(False, None, "head signature mismatch")
    if anchor_path is None:
        return ChainVerification(True)
    return _verify_anchor(Path(anchor_path), head_json, signature)


def _verify_anchor(
    anchor_path: Path, head_json: str, signature: str
) -> ChainVerification:
    if not anchor_path.exists():
        return ChainVerification(False, None, "anchor log does not exist")
    latest = ""
    with anchor_path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                latest = line
    if not latest:
        return ChainVerification(False, None, "anchor log is empty")
    try:
        anchor = json.loads(latest)
    except json.JSONDecodeError:
        return ChainVerification(False, None, "anchor log is corrupt")
    if not isinstance(anchor, dict):
        return ChainVerification(False, None, "anchor log is corrupt")
    if anchor.get("alg") != "HMAC-SHA256":
        return ChainVerification(False, None, "anchor signature algorithm mismatch")
    if str(anchor.get("signature", "")) != signature:
        return ChainVerification(False, None, "anchor signature mismatch")
    head = anchor.get("head")
    if not isinstance(head, dict):
        return ChainVerification(False, None, "anchor head mismatch")
    if _canonical_json(head) != head_json:
        return ChainVerification(False, None, "anchor head mismatch")
    return ChainVerification(True)


def _verify_chain_python(path: Path) -> ChainVerification:
    """Python reference verifier used as the parity oracle for Rust."""
    prev_hash = _GENESIS
    expected_seq = 0
    last_hash = _GENESIS
    last_seq = -1
    previous_hash = _GENESIS
    previous_seq = -1
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
            previous_hash = last_hash
            previous_seq = last_seq
            prev_hash = recomputed
            last_hash = recomputed
            last_seq = expected_seq
            expected_seq += 1

    head_path = path.with_suffix(path.suffix + ".head")
    if head_path.exists():
        head = json.loads(head_path.read_text(encoding="utf-8"))
        if head.get("seq") != last_seq or head.get("entry_hash") != last_hash:
            if (
                last_seq == previous_seq + 1
                and head.get("seq") == previous_seq
                and head.get("entry_hash") == previous_hash
            ):
                return ChainVerification(
                    True,
                    None,
                    "head sidecar behind latest entry (recoverable crash window)",
                )
            return ChainVerification(
                False, last_seq, "head sidecar mismatch (tail truncated)"
            )
    return ChainVerification(True)
