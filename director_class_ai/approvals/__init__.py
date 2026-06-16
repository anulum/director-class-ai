# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval workflow

"""Durable, digest-scoped human-approval workflow for escalated actions."""

from .policy import ApprovalPolicy
from .queue import ApprovalQueue, ApprovalTicket

__all__ = ["ApprovalPolicy", "ApprovalQueue", "ApprovalTicket"]
