# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy drift monitor

"""Alarm when a live posture diverges from the approved revision.

Guardrail-as-Code, increment 3b. A change can only become the approved posture
through review (increment 3a); this monitor closes the other half — a live
profile that a deployment is actually running may still drift away from the
approved revision through an out-of-band edit. :class:`PolicyDriftMonitor`
compares the live profile against the approved revision and, when they differ,
emits a structured :class:`PolicyDriftEvent` to a pluggable sink.

The sink is any ``Callable[[PolicyDriftEvent], None]`` — an operator wires it to
the tamper-evident audit trail so an unauthorised relaxation is recorded with the
approved and live content addresses and the exact fields that drifted, rather
than silently governing live actions.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .profile import Profile
from .revision import PolicyFieldChange, PolicyRevision, profile_digest

__all__ = ["PolicyDriftEvent", "PolicyDriftMonitor"]


@dataclass(frozen=True)
class PolicyDriftEvent:
    """A detected divergence of a live posture from the approved revision.

    Attributes
    ----------
    approved_digest : str
        Content address of the approved revision the live profile should match.
    live_digest : str
        Content address of the live profile that drifted.
    changes : tuple of PolicyFieldChange
        The fields where the live posture differs from the approved one.
    detected_at : str
        When the drift was detected (caller-supplied ISO timestamp).
    """

    approved_digest: str
    live_digest: str
    changes: tuple[PolicyFieldChange, ...]
    detected_at: str


class PolicyDriftMonitor:
    """Compare a live posture to the approved revision and alarm on drift."""

    def __init__(
        self,
        approved: PolicyRevision,
        *,
        sink: Callable[[PolicyDriftEvent], None] | None = None,
    ) -> None:
        """Guard against ``approved``, emitting drift events to ``sink``.

        Parameters
        ----------
        approved : PolicyRevision
            The approved revision a live profile is expected to match.
        sink : callable, optional
            Receives a :class:`PolicyDriftEvent` whenever drift is detected; when
            omitted, :meth:`check` still returns the event but emits nothing.
        """
        self._approved = approved
        self._sink = sink

    @property
    def approved(self) -> PolicyRevision:
        """Return the approved revision this monitor guards against."""
        return self._approved

    def check(self, live: Profile, *, detected_at: str) -> PolicyDriftEvent | None:
        """Return and emit a drift event when ``live`` differs from the approved.

        Parameters
        ----------
        live : Profile
            The profile a deployment is currently running.
        detected_at : str
            When the check was run (ISO timestamp), recorded on any event.

        Returns
        -------
        PolicyDriftEvent or None
            The drift event when the live profile diverges from the approved
            revision (also passed to the sink, if one is wired); ``None`` when the
            live profile still matches the approved posture.
        """
        changes = self._approved.drift(live)
        if not changes:
            return None
        event = PolicyDriftEvent(
            approved_digest=self._approved.digest,
            live_digest=profile_digest(live),
            changes=changes,
            detected_at=detected_at,
        )
        if self._sink is not None:
            self._sink(event)
        return event
