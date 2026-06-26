# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — exposure case corpus loader

"""Load an A/B exposure case corpus from JSON.

:class:`~director_class_ai.policy.exposure.PostureExposure` replays a set of
detector-signal cases under two postures. When that set is driven from the CLI it
arrives as a JSON corpus — a pre-computed detector output per request — that this
module turns into :class:`~director_class_ai.policy.exposure.ExposureCase`
objects. The corpus is deliberately the detector *output* (plane, score, signal
type), not raw text, so a posture can be compared offline without re-running any
model.

Corpus shape::

    {"cases": [
        {"label": "row-1", "provenance": "user", "signals": [
            {"detector": "shell_guard", "plane": "action", "score": 0.5,
             "locus": "action", "signal_type": "destructive_command",
             "severity": "high"}
        ],
         "capability_context": {"subject": "agent", "tool": "fs/read_file", ...},
         "capability_grants": [
             {"grant_id": "read-workspace", "tool": "fs/read_file",
              "max_blast_radius": "low"}
         ]}
    ]}
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from ..core.signal import DetectorSignal, Locus, Plane, Severity
from .capability import BlastRadius, CapabilityGrant
from .exposure import ExposureCase

__all__ = ["case_from_mapping", "load_cases", "signal_from_mapping"]


def signal_from_mapping(data: Mapping[str, Any]) -> DetectorSignal:
    """Build one detector signal from a corpus mapping.

    Parameters
    ----------
    data : mapping
        Keys ``detector``, ``plane``, ``score``, ``locus``, ``signal_type`` are
        required; ``severity`` (name, case-insensitive) defaults to ``MEDIUM``.

    Returns
    -------
    DetectorSignal
        The reconstructed signal.
    """
    return DetectorSignal(
        detector=data["detector"],
        plane=Plane(data["plane"]),
        score=data["score"],
        locus=Locus(data["locus"]),
        signal_type=data["signal_type"],
        severity=Severity[str(data.get("severity", "MEDIUM")).upper()],
    )


def case_from_mapping(data: Mapping[str, Any]) -> ExposureCase:
    """Build one exposure case (label, signals, provenance) from a mapping."""
    return ExposureCase(
        label=data["label"],
        signals=tuple(signal_from_mapping(s) for s in data["signals"]),
        provenance=data.get("provenance", ""),
        capability_context=_mapping(data.get("capability_context")),
        capability_grants=tuple(
            _grant_from_mapping(grant)
            for grant in _mapping_sequence(data.get("capability_grants", ()))
        ),
    )


def load_cases(path: str | Path) -> tuple[ExposureCase, ...]:
    """Load an exposure case corpus from a JSON file.

    Parameters
    ----------
    path : str or Path
        A JSON file with a top-level ``cases`` list.

    Returns
    -------
    tuple of ExposureCase
        The corpus in file order.
    """
    with Path(path).open("rb") as fh:
        payload: dict[str, Any] = json.load(fh)
    return tuple(case_from_mapping(case) for case in payload["cases"])


def _grant_from_mapping(data: Mapping[str, Any]) -> CapabilityGrant:
    """Build one capability grant from a corpus mapping."""
    return CapabilityGrant(
        grant_id=str(data["grant_id"]),
        subject=str(data.get("subject", "*")),
        tenant=str(data.get("tenant", "*")),
        session=str(data.get("session", "*")),
        source_origin=str(data.get("source_origin", "*")),
        tool=str(data.get("tool", "*")),
        resource=str(data.get("resource", "*")),
        action=str(data.get("action", "*")),
        max_blast_radius=_blast_radius(data.get("max_blast_radius", "low")),
        expires_at=_integer(data.get("expires_at", 0)),
        approval_required=bool(data.get("approval_required", False)),
    )


def _blast_radius(value: object) -> BlastRadius:
    """Parse a JSON blast-radius value."""
    if isinstance(value, BlastRadius):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return BlastRadius(value)
    return BlastRadius[str(value or "low").upper()]


def _integer(value: object) -> int:
    """Parse an integer JSON field without accepting booleans."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _mapping(value: object) -> Mapping[str, object]:
    """Return ``value`` when it is a JSON object, otherwise an empty mapping."""
    return cast(Mapping[str, object], value) if isinstance(value, Mapping) else {}


def _mapping_sequence(value: object) -> tuple[Mapping[str, Any], ...]:
    """Return the mapping items from a JSON array-like value."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(
        cast(Mapping[str, Any], item) for item in value if isinstance(item, Mapping)
    )
