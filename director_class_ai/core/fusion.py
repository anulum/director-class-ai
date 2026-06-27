# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
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
    # Legacy default band. Per-plane margins below inherit this value when left
    # unset, so existing profiles keep their old posture.
    uncertainty_margin: float = 0.15
    # A risk within a plane-specific band of that plane's threshold is
    # "borderline" and escalates to a human. Set a plane margin to 0 to disable
    # borderline escalation for that plane while leaving the others unchanged.
    content_uncertainty_margin: float | None = None
    integrity_uncertainty_margin: float | None = None
    action_uncertainty_margin: float | None = None
    # Action signal types whose danger is injection / exfiltration / structural
    # taint rather than an inherently-destructive but potentially user-authorised
    # operation. An action carrying one of these is never downgraded from a hard
    # block to a human-approval escalation on the strength of "the user asked": a
    # tainted argument, an untrusted origin, or a data-exfiltration shape is the
    # threat the action plane exists to stop, not an authorised op.
    taint_signal_types: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"origin_taint", "mcp_tool_call", "exfiltration"}
            | {"causal_takeover"}
            | {"mcp_remote_auth"}
            | {"capability_context_missing", "capability_missing"}
            | {"capability_origin_denied"}
            | {
                "mcp_underpopulated_registration",
                "mcp_unsigned_registration",
                "mcp_registration_signature_mismatch",
                "mcp_schema_drift",
                "mcp_lookalike_tool",
                "mcp_transport_mismatch",
                "mcp_argument_schema_violation",
            }
            | {
                "browser_prompt_injection",
                "browser_malicious_iframe",
                "browser_popup_hijack",
                "browser_clipboard_exfiltration",
                "browser_unsafe_download",
                "browser_cross_site_task_drift",
            }
            | {
                "memory_poisoning",
                "stale_tool_schema",
                "persistent_instruction_injection",
                "delayed_malicious_objective",
                "task_plan_drift",
                "memory_secret_leakage",
            }
        )
    )
    # Catastrophic action classes that must not be converted from block to
    # approval merely because the action provenance says "user". These operations
    # destroy storage, erase auditability, remove availability, or grant durable
    # privilege; a single click is not a proportionate control.
    never_soften_signal_types: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "availability_loss",
                "bucket_deletion",
                "datastore_drop",
                "datastore_flush",
                "destructive_command",
                "disk_overwrite",
                "filesystem_format",
                "fork_bomb",
                "history_rewrite",
                "infra_teardown",
                "process_kill",
                "privilege_escalation",
                "sql_drop",
                "sql_truncate",
            }
        )
    )
    plane_mode: dict[Plane, FusionMode] = field(
        default_factory=lambda: {
            Plane.CONTENT: FusionMode.FAIL_OPEN,
            Plane.INTEGRITY: FusionMode.FAIL_OPEN,
            Plane.ACTION: FusionMode.FAIL_CLOSED,
        }
    )

    def __post_init__(self) -> None:
        """Validate global and per-plane uncertainty margins."""
        for attr in (
            "uncertainty_margin",
            "content_uncertainty_margin",
            "integrity_uncertainty_margin",
            "action_uncertainty_margin",
        ):
            value = getattr(self, attr)
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{attr} must be in [0, 1], got {value}")

    def content_risk(self, signals: Sequence[DetectorSignal]) -> float:
        """Fuse content/integrity signals — calibrated noisy-OR by default."""
        return _noisy_or([s.weighted_score for s in signals])

    def uncertainty_margin_for(self, plane: Plane) -> float:
        """Return the review band configured for one signal plane."""
        if plane is Plane.CONTENT:
            return (
                self.uncertainty_margin
                if self.content_uncertainty_margin is None
                else self.content_uncertainty_margin
            )
        if plane is Plane.INTEGRITY:
            return (
                self.uncertainty_margin
                if self.integrity_uncertainty_margin is None
                else self.integrity_uncertainty_margin
            )
        return (
            self.uncertainty_margin
            if self.action_uncertainty_margin is None
            else self.action_uncertainty_margin
        )

    def user_authorised_destructive(
        self, objectors: Sequence[DetectorSignal], provenance: str
    ) -> bool:
        """Return whether a destructive action is the user's own request, taint-free.

        The action plane blocks destructive commands by default. When the request
        is *explicitly user-originated* (``provenance == "user"``), and no objector
        is an injection / exfiltration / structural-taint class or an irreversible
        never-soften class, the proportionate control is a human approval gate
        rather than a dead hard block. A tainted argument, an untrusted origin, a
        data-exfiltration shape, or a catastrophic operation such as disk overwrite
        keeps the hard block regardless of provenance.
        """
        if provenance.strip().lower() != "user":
            return False
        return not any(
            s.signal_type in self.taint_signal_types
            or s.signal_type in self.never_soften_signal_types
            for s in objectors
        )

    def never_softened(self, objectors: Sequence[DetectorSignal]) -> bool:
        """Return whether any objector belongs to a non-approval action class."""
        return any(s.signal_type in self.never_soften_signal_types for s in objectors)


def fuse(
    signals: Sequence[DetectorSignal],
    policy: FusionPolicy | None = None,
    *,
    provenance: str = "",
) -> Verdict:
    """Resolve parallel detector signals into one verdict across planes.

    ``provenance`` is the request's ``action_provenance`` (``"user"`` when a human
    explicitly originated the action). It gates authorised-destructive routing: a
    user-originated, taint-free destructive action is escalated to a human rather
    than hard-blocked. Defaulting to ``""`` keeps every existing caller fail-closed.
    """
    policy = policy or FusionPolicy()
    by_plane: dict[Plane, list[DetectorSignal]] = {}
    for sig in signals:
        by_plane.setdefault(sig.plane, []).append(sig)

    plane_risk: dict[Plane, float] = {}
    firing: list[DetectorSignal] = []
    requires_human = False
    allow = True
    reasons: list[str] = []

    def borderline(risk: float, threshold: float, plane: Plane) -> bool:
        margin = policy.uncertainty_margin_for(plane)
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
        elif borderline(risk, threshold, plane):
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
            firing.extend(objectors)
            if policy.user_authorised_destructive(objectors, provenance):
                # User-originated, taint-free destructive op: route to a human
                # approval gate instead of a dead hard block. ``allow`` is left
                # untouched, so a content/integrity objection that already blocked
                # still wins — only the action-plane verdict softens to escalation.
                requires_human = True
                reasons.append(
                    f"action escalated: user-authorised destructive op, "
                    f"{len(objectors)} objector(s), risk {risk:.2f} → human approval"
                )
            else:
                allow = False
                reasons.append(
                    f"action blocked: {len(objectors)} objector(s), risk {risk:.2f}"
                )
                if policy.never_softened(objectors):
                    reasons.append("never-soften irreversible action class")
                elif any(s.severity >= Severity.CRITICAL for s in objectors):
                    requires_human = True
                    reasons.append("CRITICAL severity → human approval required")
        elif borderline(risk, policy.action_block_threshold, Plane.ACTION):
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
