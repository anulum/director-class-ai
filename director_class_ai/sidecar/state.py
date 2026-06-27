# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — durable halt-switch state

"""Durable halt-switch state owned by a sidecar process.

The in-process SDK and gateway hooks read this file as an external authority.
The file can be placed in a directory writable only by an operator-owned sidecar,
so a governed agent can observe the halt state without being able to rewrite it.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..core.durability import atomic_write_text

__all__ = ["HaltSwitchReader", "HaltSwitchSnapshot", "LocalHaltSwitch"]

_SCHEMA_VERSION = "director-class-ai.halt-state.v1"


class HaltSwitchReader(Protocol):
    """Read-only authority consulted before a governed action executes."""

    def snapshot(self) -> HaltSwitchSnapshot:
        """Return the latest halt-switch snapshot."""
        ...


@dataclass(frozen=True)
class HaltSwitchSnapshot:
    """One durable halt-switch state snapshot."""

    halted: bool
    reason: str = ""
    actor: str = ""
    updated_at: str = ""
    generation: int = 0

    @classmethod
    def active(
        cls,
        *,
        reason: str,
        actor: str,
        updated_at: str,
        generation: int,
    ) -> HaltSwitchSnapshot:
        """Build a halted snapshot with operator attribution."""
        return cls(
            halted=True,
            reason=reason,
            actor=actor,
            updated_at=updated_at,
            generation=generation,
        )

    @classmethod
    def inactive(
        cls,
        *,
        reason: str = "",
        actor: str = "",
        updated_at: str = "",
        generation: int = 0,
    ) -> HaltSwitchSnapshot:
        """Build an unhalted snapshot with optional operator attribution."""
        return cls(
            halted=False,
            reason=reason,
            actor=actor,
            updated_at=updated_at,
            generation=generation,
        )

    def to_json_dict(self) -> dict[str, object]:
        """Return deterministic JSON data for durable persistence."""
        return {
            "schema_version": _SCHEMA_VERSION,
            "halted": self.halted,
            "reason": self.reason,
            "actor": self.actor,
            "updated_at": self.updated_at,
            "generation": self.generation,
        }

    @classmethod
    def from_json_dict(cls, data: object) -> HaltSwitchSnapshot:
        """Parse and validate a persisted halt-switch snapshot."""
        if not isinstance(data, dict):
            raise ValueError("halt state must be a JSON object")
        if data.get("schema_version") != _SCHEMA_VERSION:
            raise ValueError("unsupported halt state schema")
        generation = data.get("generation", 0)
        if not isinstance(generation, int) or generation < 0:
            raise ValueError("halt state generation must be a non-negative integer")
        return cls(
            halted=bool(data.get("halted", False)),
            reason=_string(data.get("reason")),
            actor=_string(data.get("actor")),
            updated_at=_string(data.get("updated_at")),
            generation=generation,
        )


class LocalHaltSwitch:
    """Durable local halt switch backed by one JSON file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def snapshot(self) -> HaltSwitchSnapshot:
        """Load the current halt state, defaulting to unhalted when absent."""
        if not self.path.exists():
            return HaltSwitchSnapshot.inactive()
        loaded = json.loads(self.path.read_text(encoding="utf-8"))
        return HaltSwitchSnapshot.from_json_dict(loaded)

    def halt(
        self,
        *,
        reason: str,
        actor: str,
        updated_at: str | None = None,
    ) -> HaltSwitchSnapshot:
        """Persist a halted state with an operator reason and actor."""
        if not reason.strip():
            raise ValueError("halt reason is required")
        if not actor.strip():
            raise ValueError("halt actor is required")
        prior = self.snapshot()
        snapshot = HaltSwitchSnapshot.active(
            reason=reason,
            actor=actor,
            updated_at=updated_at or _now(),
            generation=prior.generation + 1,
        )
        self._write(snapshot)
        return snapshot

    def resume(
        self,
        *,
        reason: str,
        actor: str,
        updated_at: str | None = None,
    ) -> HaltSwitchSnapshot:
        """Persist an unhalted state with an operator reason and actor."""
        if not reason.strip():
            raise ValueError("resume reason is required")
        if not actor.strip():
            raise ValueError("resume actor is required")
        prior = self.snapshot()
        snapshot = HaltSwitchSnapshot.inactive(
            reason=reason,
            actor=actor,
            updated_at=updated_at or _now(),
            generation=prior.generation + 1,
        )
        self._write(snapshot)
        return snapshot

    def _write(self, snapshot: HaltSwitchSnapshot) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            self.path,
            json.dumps(
                snapshot.to_json_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


def _now() -> str:
    """Return a UTC timestamp for operator state changes."""
    return dt.datetime.now(dt.UTC).isoformat()


def _string(value: object) -> str:
    """Return ``value`` when it is a string, else an empty string."""
    return value if isinstance(value, str) else ""
