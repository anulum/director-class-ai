# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
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
        ]}
    ]}
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..core.signal import DetectorSignal, Locus, Plane, Severity
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
