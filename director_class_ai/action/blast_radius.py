# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — blast-radius detector (action plane, tier 0)

"""Estimate how far an action reaches and how reversible it is.

Where the destructive-command detector matches *known* catastrophic patterns,
this scores the *general* risk dimensions of any action, so a dangerous command
with no exact rule — "delete the production database backups", "overwrite every
config under /etc" — is still flagged by the shape of what it does:

* irreversibility — the verb destroys rather than reads;
* scope — it names production / live / main;
* system target — it touches /etc, /var, /, ~, C:\\Windows;
* breadth — recursion, wildcards, --all, --force, "everything".

The dimensions are summed into a risk in [0, 1] and mapped to a severity band.
Low-risk actions emit nothing (no noise on ``ls`` or a scoped read); the detector
fires from the MEDIUM band up, and the fail-closed fusion decides from there.
"""

from __future__ import annotations

import re

from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)
from ._lexicon import BREADTH, IRREVERSIBLE, PRODUCTION, SYSTEM_TARGET

__all__ = ["BlastRadiusDetector"]

# Dimension weights — irreversibility dominates, scope and target next.
_WEIGHTS: tuple[tuple[re.Pattern[str], float, str], ...] = (
    (IRREVERSIBLE, 0.40, "irreversible operation"),
    (SYSTEM_TARGET, 0.25, "system / high-value target"),
    (PRODUCTION, 0.20, "production scope"),
    (BREADTH, 0.15, "recursive / wildcard / force breadth"),
)
_PRINT_SEGMENT = re.compile(
    r"(?:^|[;&|]\s*)"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|[^\s;&|]+)\s+)*"
    r"(?:echo|printf)\b[^;&|]*",
    re.IGNORECASE,
)


def _severity(risk: float) -> Severity:
    # The detector only fires on irreversible + scope, so the floor risk is already
    # 0.60 (irreversible + production); CRITICAL once a second scope signal lands.
    return Severity.CRITICAL if risk >= 0.8 else Severity.HIGH


class BlastRadiusDetector:
    """Tier-0 action-plane detector scoring an action's reach and reversibility."""

    name = "blast_radius"
    plane = Plane.ACTION
    tier = 0

    #: minimum risk before the detector emits a signal (below this = low blast)
    floor: float = 0.4

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        command = _PRINT_SEGMENT.sub(" ", (request.action or "")).strip()
        if not command:
            return None
        risk = 0.0
        reasons: list[str] = []
        for pattern, weight, label in _WEIGHTS:
            if pattern.search(command):
                risk += weight
                reasons.append(label)
        risk = min(risk, 1.0)
        # An irreversible verb is necessary but not sufficient: it must reach a
        # *scope* — a system / high-value target or a production reference. An
        # irreversible verb with only local breadth (a scoped "delete temp",
        # "rm -rf node_modules") is left to the path-aware command rules, so the
        # blast estimator stops false-blocking ordinary local cleanups.
        scoped = SYSTEM_TARGET.search(command) or PRODUCTION.search(command)
        if risk < self.floor or not IRREVERSIBLE.search(command) or not scoped:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=risk,
            locus=Locus.ACTION,
            signal_type="blast_radius",
            severity=_severity(risk),
            rationale=", ".join(reasons),
        )
