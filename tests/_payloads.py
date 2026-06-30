# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — typed accessors for redacted JSON payloads in tests

"""Type-narrowing accessors for the ``dict[str, object]`` payloads that the
governance surfaces emit (audit events, decision records, evidence packages,
benchmark metrics, service responses, and manifests).

The detectors, governor, gateway, and benchmark code deliberately return
deterministic JSON-shaped mappings whose values are heterogeneous, so the
public types are ``object``. Tests need to index, iterate, compare, and run
membership checks against those values under ``mypy --strict``. Each accessor
asserts the runtime shape it claims, so it narrows the type for the type checker
*and* strengthens the assertion — a malformed payload fails inside the accessor
with the offending key and observed type rather than producing an opaque
``AttributeError`` or ``TypeError`` later in the test body.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence


def section(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    """Return a nested mapping field, asserting the value is a mapping."""
    value = payload[key]
    assert isinstance(value, Mapping), f"{key} is not a mapping: {type(value)!r}"
    return value


def seq(payload: Mapping[str, object], key: str) -> Sequence[object]:
    """Return a sequence field (list or tuple, never text), asserting its shape."""
    value = payload[key]
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes)), (
        f"{key} is not a non-text sequence: {type(value)!r}"
    )
    return value


def rows(payload: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    """Return a sequence-of-mappings field, asserting every item is a mapping."""
    value = payload[key]
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes)), (
        f"{key} is not a non-text sequence: {type(value)!r}"
    )
    extracted: list[Mapping[str, object]] = []
    for item in value:
        assert isinstance(item, Mapping), f"{key} item is not a mapping: {type(item)!r}"
        extracted.append(item)
    return extracted


def metric(payload: Mapping[str, object], key: str) -> float:
    """Return a numeric field as a float, asserting the value is numeric."""
    value = payload[key]
    assert isinstance(value, (int, float)), f"{key} is not numeric: {type(value)!r}"
    return float(value)


def text(payload: Mapping[str, object], key: str) -> str:
    """Return a string field, asserting the value is a string."""
    value = payload[key]
    assert isinstance(value, str), f"{key} is not a str: {type(value)!r}"
    return value
