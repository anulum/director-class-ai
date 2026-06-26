# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — runtime posture enforcement

"""Resolve and enforce runtime Guardrail-as-Code posture state.

The operator ledger is useful only when a runtime surface can prove which
approved posture governs it. This module provides the shared check used by
runtime entry points: load the approved head, optionally require that it exists,
and optionally compare a live profile against that head before any action is
reviewed.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..core.fusion import FusionPolicy
from .drift import PolicyDriftEvent
from .governance import PolicyGovernance
from .loader import load_profile_file

__all__ = ["RuntimePostureResolution", "resolve_runtime_posture"]


@dataclass(frozen=True)
class RuntimePostureResolution:
    """Resolved runtime policy and any fail-closed posture finding."""

    fusion_policy: FusionPolicy | None
    drift_event: PolicyDriftEvent | None = None
    blocking_signal: str = ""
    rationale: str = ""

    @property
    def blocked(self) -> bool:
        """Whether runtime posture state must block the action before review."""
        return bool(self.blocking_signal)


def resolve_runtime_posture(
    policy_store: str | Path,
    *,
    live_profile: str | Path | None = None,
    require_approved: bool = False,
    detected_at: str,
) -> RuntimePostureResolution:
    """Resolve the approved runtime posture and detect live-profile drift.

    Parameters
    ----------
    policy_store : str or Path
        Durable Guardrail-as-Code governance ledger.
    live_profile : str or Path, optional
        TOML profile that represents the posture a deployment is currently
        running. When supplied, it must match the approved head.
    require_approved : bool, default=False
        When true, the absence of an approved head is a fail-closed runtime
        configuration error instead of a safe-default fallback.
    detected_at : str
        Timestamp recorded on any emitted drift event.

    Returns
    -------
    RuntimePostureResolution
        The active fusion policy when one is approved, plus a blocking finding
        when the posture is missing or drifted.
    """
    governance = PolicyGovernance.load(policy_store)
    head = governance.head
    if head is None:
        if require_approved or live_profile is not None:
            return RuntimePostureResolution(
                fusion_policy=None,
                blocking_signal="policy_head_missing",
                rationale="approved Guardrail-as-Code head is required",
            )
        return RuntimePostureResolution(fusion_policy=None)

    if live_profile is not None:
        event = governance.drift_check(
            load_profile_file(live_profile),
            detected_at=detected_at,
        )
        if event is not None:
            return RuntimePostureResolution(
                fusion_policy=head.profile.to_fusion_policy(),
                drift_event=event,
                blocking_signal="policy_runtime_drift",
                rationale="live runtime posture diverges from approved policy head",
            )
    return RuntimePostureResolution(fusion_policy=head.profile.to_fusion_policy())
