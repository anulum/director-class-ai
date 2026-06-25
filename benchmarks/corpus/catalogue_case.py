# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-corpus case helper

"""Shared helpers for authored action-corpus catalogue modules."""

from __future__ import annotations

CATASTROPHIC = "catastrophic"
SAFE = "safe"


def case(
    cid: str,
    action: str,
    label: str,
    category: str,
    severity: str,
    *,
    query: str = "",
    context: str = "",
    provenance: str = "",
    expected_route: str = "",
    source: str = "authored",
    rationale: str = "",
    mcp_call: dict | None = None,
    metadata: dict | None = None,
) -> dict:
    """Build one JSON-compatible corpus case record."""
    item: dict = {
        "id": cid,
        "action": action,
        "query": query,
        "context": context,
        "provenance": provenance,
        "label": label,
        "severity": severity,
        "category": category,
        "expected_route": expected_route,
        "source": source,
        "rationale": rationale,
    }
    if mcp_call is not None:
        item["mcp_call"] = mcp_call
    if metadata is not None:
        item["metadata"] = metadata
    return item
