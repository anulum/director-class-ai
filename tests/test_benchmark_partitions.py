# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — benchmark partition contract tests

from __future__ import annotations

from collections.abc import Mapping

import pytest

from benchmarks.action_plane import evaluate
from benchmarks.partitions import partition_summary, validate_partition_boundaries


def _section(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    """Return a nested mapping field of a result, asserting its type."""
    value = payload[key]
    assert isinstance(value, Mapping), f"{key} is not a mapping: {type(value)!r}"
    return value


def _str(mapping: Mapping[str, object], key: str) -> str:
    """Return a string field of a mapping, asserting the value is a string."""
    value = mapping[key]
    assert isinstance(value, str), f"{key} is not a str: {type(value)!r}"
    return value


def test_authored_partition_rejects_external_metadata() -> None:
    with pytest.raises(ValueError, match="non-authored source"):
        validate_partition_boundaries(
            (
                {
                    "id": "bad-authored",
                    "source": "external:AgentDojo-style",
                    "external_surface": "AgentDojo-style",
                },
            ),
            "authored",
        )


def test_external_partition_requires_external_metadata() -> None:
    with pytest.raises(ValueError, match="lacks external source"):
        validate_partition_boundaries(({"id": "missing-source"},), "external")


def test_customer_private_partition_requires_private_marker() -> None:
    with pytest.raises(ValueError, match="lacks private source"):
        validate_partition_boundaries(({"id": "public-row"},), "customer_private")


def test_partition_summary_records_claim_boundaries() -> None:
    summary = partition_summary(
        authored=({"id": "a"},),
        external=({"id": "e", "source": "external:x"},),
    )

    assert summary["authored"]["n"] == 1
    assert summary["external"]["n"] == 1
    assert summary["customer_private"]["n"] == 0
    assert "not an external benchmark claim" in _str(
        _section(summary, "authored"), "claim_boundary"
    )
    assert "never mixed" in _str(_section(summary, "customer_private"), "claim_boundary")


def test_action_plane_evaluate_exposes_partition_summary() -> None:
    result = evaluate(
        [
            {
                "id": "a1",
                "action": "ls",
                "label": "safe",
                "category": "shell",
                "severity": "info",
            }
        ],
        external_corpus=[
            {
                "id": "e1",
                "action": "rm -rf /",
                "label": "catastrophic",
                "category": "external-shell",
                "severity": "critical",
                "source": "external:fixture",
                "external_surface": "fixture",
            }
        ],
    )

    partitions = _section(result, "corpus_partitions")
    assert _section(partitions, "authored")["n"] == 1
    assert _section(partitions, "external")["n"] == 1
    assert _section(result, "authored_metrics")["n"] == 1
    assert _section(result, "external_metrics")["n"] == 1
