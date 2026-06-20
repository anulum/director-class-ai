# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — approval workflow

"""Durable, digest-scoped human-approval workflow for escalated actions."""

from .policy import ApprovalPolicy
from .queue import ApprovalQueue, ApprovalTicket
from .transport import (
    APPROVAL_AUTH_HEADER,
    APPROVAL_SIGNATURE_HEADER,
    ApprovalService,
    ApprovalServiceConfig,
    ApprovalServiceResponse,
    ApprovalWebhookEvent,
    ApprovalWebhookSink,
    OperatorApprovalConsole,
    OperatorApprovalHTTPServer,
)

__all__ = [
    "APPROVAL_AUTH_HEADER",
    "APPROVAL_SIGNATURE_HEADER",
    "ApprovalPolicy",
    "ApprovalQueue",
    "ApprovalService",
    "ApprovalServiceConfig",
    "ApprovalServiceResponse",
    "ApprovalTicket",
    "ApprovalWebhookEvent",
    "ApprovalWebhookSink",
    "OperatorApprovalConsole",
    "OperatorApprovalHTTPServer",
]
