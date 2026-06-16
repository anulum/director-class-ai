# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — plane-aware fusion of detector signals into a verdict

"""Fuse the parallel detectors' signals into one governance verdict.

The fusion is deliberately *not* a single aggregation. Each plane has its own
risk and its own way of resolving uncertainty:

* **Content / integrity (fail-open).** Calibrated noisy-OR over the plane's
  signals: independent detectors that each say "probably fine" should not stack
  into a false alarm, but several weak agreements should raise risk. A response
  is flagged only when the fused risk clears the plane threshold.
* **Action (fail-closed).** The asymmetry inverts: a single credible
  destructive-action signal blocks, and anything uncertain at ``CRITICAL``
  severity escalates to a human rather than being allowed. Silence is not
  consent — an action is allowed only when no competent detector objects.

This module ships a transparent default policy. A learned meta-classifier can
replace :meth:`FusionPolicy.content_risk` without touching callers, once the
offline ablation says it beats the calibrated noisy-OR.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from .signal import DetectorSignal, FusionMode, Plane, Severity

__all__ = ["Verdict", "FusionPolicy", "fuse"]


@dataclass(frozen=True)
class Verdict:
    """The fused governance decision over all planes."""

    allow: bool
    risk: float  # overall risk in [0, 1]
    requires_human: bool
    plane_risk: dict[Plane, float] = field(default_factory=dict)
    firing: tuple[DetectorSignal, ...] = ()
    rationale: str = ""


def _noisy_or(scores: Sequence[float]) -> float:
    """Probability at least one independent detector is right: 1 - Π(1 - s)."""
    product = 1.0
    for s in scores:
        product *= 1.0 - max(0.0, min(1.0, s))
    return 1.0 - product


@dataclass
class FusionPolicy:
    """Tunable thresholds and per-plane modes for :func:`fuse`."""

    content_threshold: float = 0.5
    integrity_threshold: float = 0.5
    action_block_threshold: float = 0.3  # low: fail-closed leans to blocking
    # A risk landing within this band of a plane's threshold is "borderline" —
    # neither confidently safe nor confidently a problem — and is escalated to a
    # human. A split judge panel lands here, which is exactly when a person should
    # look. Set to 0 to disable borderline escalation.
    uncertainty_margin: float = 0.15
    plane_mode: dict[Plane, FusionMode] = field(
        default_factory=lambda: {
            Plane.CONTENT: FusionMode.FAIL_OPEN,
            Plane.INTEGRITY: FusionMode.FAIL_OPEN,
            Plane.ACTION: FusionMode.FAIL_CLOSED,
        }
    )

    def content_risk(self, signals: Sequence[DetectorSignal]) -> float:
        """Fuse content/integrity signals — calibrated noisy-OR by default."""
        return _noisy_or([s.weighted_score for s in signals])


def fuse(
    signals: Sequence[DetectorSignal], policy: FusionPolicy | None = None
) -> Verdict:
    """Resolve parallel detector signals into one verdict across planes."""
    policy = policy or FusionPolicy()
    by_plane: dict[Plane, list[DetectorSignal]] = {}
    for sig in signals:
        by_plane.setdefault(sig.plane, []).append(sig)

    plane_risk: dict[Plane, float] = {}
    firing: list[DetectorSignal] = []
    requires_human = False
    allow = True
    reasons: list[str] = []
    margin = policy.uncertainty_margin

    def borderline(risk: float, threshold: float) -> bool:
        return margin > 0 and abs(risk - threshold) <= margin

    # Content + integrity: fail-open, flag only above threshold.
    for plane, threshold in (
        (Plane.CONTENT, policy.content_threshold),
        (Plane.INTEGRITY, policy.integrity_threshold),
    ):
        plane_signals = by_plane.get(plane, [])
        if not plane_signals:
            continue
        risk = policy.content_risk(plane_signals)
        plane_risk[plane] = risk
        if risk >= threshold:
            allow = False
            firing.extend(s for s in plane_signals if s.weighted_score > 0)
            reasons.append(f"{plane.value} risk {risk:.2f} >= {threshold:.2f}")
        elif borderline(risk, threshold):
            requires_human = True
            reasons.append(f"{plane.value} risk {risk:.2f} borderline → review")

    # Action: fail-closed. Any credible objection blocks; a CRITICAL objection or a
    # borderline risk escalates to a human rather than being silently allowed.
    action_signals = by_plane.get(Plane.ACTION, [])
    if action_signals:
        risk = max(s.weighted_score for s in action_signals)
        plane_risk[Plane.ACTION] = risk
        objectors = [
            s for s in action_signals if s.weighted_score >= policy.action_block_threshold
        ]
        if objectors:
            allow = False
            firing.extend(objectors)
            reasons.append(
                f"action blocked: {len(objectors)} objector(s), risk {risk:.2f}"
            )
            if any(s.severity >= Severity.CRITICAL for s in objectors):
                requires_human = True
                reasons.append("CRITICAL severity → human approval required")
        elif borderline(risk, policy.action_block_threshold):
            requires_human = True
            reasons.append(f"action risk {risk:.2f} borderline → human approval")

    overall = max(plane_risk.values(), default=0.0)
    return Verdict(
        allow=allow,
        risk=overall,
        requires_human=requires_human,
        plane_risk=plane_risk,
        firing=tuple(firing),
        rationale="; ".join(reasons) or "no detector objected",
    )
