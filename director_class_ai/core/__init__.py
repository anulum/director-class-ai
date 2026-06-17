# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — ensemble core

"""Plane-agnostic detector signal, fusion, ensemble, and calibration APIs."""

from .calibration import CalibrationRegistry, PlattCalibrator, fit_platt
from .ensemble import ParallelEnsembleScorer
from .fusion import FusionPolicy, Verdict, fuse
from .governor import AuditRecord, Decision, Governor
from .meta_classifier import (
    MetaClassifierFusionPolicy,
    SignalMetaClassifier,
    extract_signal_features,
    fit_signal_meta_classifier,
)
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
    "Governor",
    "Decision",
    "AuditRecord",
    "fit_platt",
    "PlattCalibrator",
    "CalibrationRegistry",
    "DetectorSignal",
    "EvaluationRequest",
    "FusionMode",
    "FusionPolicy",
    "MetaClassifierFusionPolicy",
    "Locus",
    "ParallelEnsembleScorer",
    "Plane",
    "Severity",
    "SignalMetaClassifier",
    "Span",
    "Verdict",
    "extract_signal_features",
    "fit_signal_meta_classifier",
    "fuse",
]
