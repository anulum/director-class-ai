# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — ensemble core

"""Plane-agnostic detector signal, fusion, and (forthcoming) ensemble runner."""

from .fusion import FusionPolicy, Verdict, fuse
from .signal import (
    Detector,
    DetectorSignal,
    EvaluationRequest,
    FusionMode,
    Locus,
    Plane,
    Severity,
    Span,
)

__all__ = [
    "Detector",
    "DetectorSignal",
    "EvaluationRequest",
    "FusionMode",
    "FusionPolicy",
    "Locus",
    "Plane",
    "Severity",
    "Span",
    "Verdict",
    "fuse",
]
