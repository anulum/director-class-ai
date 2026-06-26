# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval routing policy

"""Choose where an escalation is routed based on how severe it is.

Not every escalation deserves the same human. This maps a verdict to a route name
(e.g. a single on-call approver vs two-person sign-off for catastrophic actions),
so the approval workflow can send the riskiest decisions to the strictest gate.
The route is advisory metadata for the approval workflow; the queue still enforces
single-use, digest-scoped, expiring approvals regardless of route.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.fusion import Verdict
from ..core.signal import Severity

__all__ = ["ApprovalPolicy"]


@dataclass
class ApprovalPolicy:
    """Map a verdict's peak firing severity to an approval route name."""

    routes: dict[Severity, str] = field(
        default_factory=lambda: {
            Severity.CRITICAL: "dual_human",
            Severity.HIGH: "human",
            Severity.MEDIUM: "human",
        }
    )
    route_required_approvals: dict[str, int] = field(
        default_factory=lambda: {"dual_human": 2, "human": 1, "auto": 1}
    )
    default_route: str = "auto"

    def route(self, verdict: Verdict) -> str:
        """Return the approval route for the verdict's highest firing severity."""
        if not verdict.firing:
            return self.default_route
        peak = max(s.severity for s in verdict.firing)
        return self.routes.get(peak, self.default_route)

    def required_approvals(self, verdict: object) -> int:
        """Return how many distinct operators must approve this verdict."""
        if not isinstance(verdict, Verdict):
            return self.route_required_approvals.get(self.default_route, 1)
        route = self.route(verdict)
        return max(1, self.route_required_approvals.get(route, 1))
