# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — benchmark corpus partition contracts

"""Validate benchmark corpus partition boundaries.

Authored examples, imported external benchmark artefacts, and customer/private
corpora have different claim boundaries. This module keeps those partitions
explicit before metrics are computed so a report cannot accidentally mix authored
coverage with external or private evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal

__all__ = [
    "CorpusPartition",
    "partition_summary",
    "validate_partition_boundaries",
]

CorpusPartition = Literal["authored", "external", "customer_private"]

_PARTITIONS: tuple[CorpusPartition, ...] = ("authored", "external", "customer_private")


def validate_partition_boundaries(
    cases: Sequence[Mapping[str, object]],
    partition: CorpusPartition,
) -> None:
    """Reject cases whose source metadata belongs to a different partition.

    Parameters
    ----------
    cases:
        Benchmark case dictionaries to validate.
    partition:
        Partition the caller intends these rows to occupy.

    Raises
    ------
    ValueError
        If a case carries metadata for a different partition.
    """
    for index, case in enumerate(cases):
        case_id = str(case.get("id", f"<index:{index}>"))
        source = str(case.get("source", ""))
        has_external_fields = any(key.startswith("external_") for key in case)
        is_customer_private = bool(case.get("customer_private")) or source.startswith(
            "customer:"
        )
        is_external = has_external_fields or source.startswith("external:")
        if partition == "authored" and (is_external or is_customer_private):
            raise ValueError(f"authored corpus row {case_id} carries non-authored source")
        if partition == "external" and (not is_external or is_customer_private):
            raise ValueError(f"external corpus row {case_id} lacks external source")
        if partition == "customer_private" and not is_customer_private:
            raise ValueError(
                f"customer_private corpus row {case_id} lacks private source"
            )


def partition_summary(
    *,
    authored: Sequence[Mapping[str, object]],
    external: Sequence[Mapping[str, object]],
    customer_private: Sequence[Mapping[str, object]] = (),
) -> dict[str, dict[str, object]]:
    """Return count and claim boundary metadata for every corpus partition."""
    counts = {
        "authored": len(authored),
        "external": len(external),
        "customer_private": len(customer_private),
    }
    return {
        partition: {
            "n": counts[partition],
            "claim_boundary": _claim_boundary(partition),
        }
        for partition in _PARTITIONS
    }


def _claim_boundary(partition: CorpusPartition) -> str:
    if partition == "authored":
        return "internal authored regression evidence; not an external benchmark claim"
    if partition == "external":
        return "external artefact evidence; requires licence and provenance review"
    return "customer/private evidence; never mixed into public benchmark claims"
