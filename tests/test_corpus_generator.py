# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-corpus generator tests

from __future__ import annotations

import pytest

from benchmarks.corpus import build_catalogue
from benchmarks.corpus.generate import _validate, assemble


def test_assembled_corpus_reaches_the_size_bar() -> None:
    corpus = assemble()
    assert len(corpus) >= 300
    labels = {c["label"] for c in corpus}
    assert labels == {"catastrophic", "safe"}


def test_ids_are_unique_across_seed_and_catalogue() -> None:
    ids = [c["id"] for c in assemble()]
    assert len(ids) == len(set(ids))


def test_catalogue_is_deterministic() -> None:
    assert build_catalogue() == build_catalogue()


def test_catalogue_has_both_classes_and_attribution() -> None:
    cat = build_catalogue()
    assert {c["label"] for c in cat} == {"catastrophic", "safe"}
    # injected/MCP cases cite the threat-taxonomy alignment, never a copied source
    aligned = [c for c in cat if "category-aligned" in c.get("source", "")]
    assert aligned and all("copied" not in c["source"] for c in aligned)


def test_catalogue_has_causal_takeover_timelines() -> None:
    cases = [c for c in build_catalogue() if c["category"] == "causal-takeover"]

    assert {c["label"] for c in cases} == {"catastrophic", "safe"}
    assert all(c.get("metadata", {}).get("causal_timeline") for c in cases)
    assert any(c.get("provenance") in {"retrieved", "tool_output"} for c in cases)


def _row(cid: str, label: str = "safe") -> dict:
    return {
        "id": cid,
        "action": "a",
        "label": label,
        "category": "c",
        "severity": "none",
    }


class TestValidation:
    def test_duplicate_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="duplicate id"):
            _validate([_row("x"), _row("x")])

    def test_missing_field_rejected(self) -> None:
        with pytest.raises(ValueError, match="missing fields"):
            _validate([{"id": "x", "action": "a", "label": "safe"}])

    def test_bad_label_rejected(self) -> None:
        with pytest.raises(ValueError, match="bad label"):
            _validate([_row("x", "perhaps")])

    def test_single_class_rejected(self) -> None:
        with pytest.raises(ValueError, match="both classes"):
            _validate([_row("x", "safe")])
