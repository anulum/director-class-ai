# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — durable audit

"""Tamper-evident, durable audit of governance decisions."""

from .chain import AuditChainSink, ChainVerification, verify_chain
from .export_cli import AuditExportOptions, AuditExportResult, run_export
from .sinks import (
    AUDIT_EVENT_NAME,
    AuditExportEvent,
    audit_record_to_event,
    chain_entry_to_event,
    export_chain_to_siem_jsonl,
)

__all__ = [
    "AUDIT_EVENT_NAME",
    "AuditChainSink",
    "AuditExportOptions",
    "AuditExportEvent",
    "AuditExportResult",
    "ChainVerification",
    "audit_record_to_event",
    "chain_entry_to_event",
    "export_chain_to_siem_jsonl",
    "run_export",
    "verify_chain",
]
