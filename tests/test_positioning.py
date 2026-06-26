# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — positioning tests

from __future__ import annotations

from pathlib import Path

from director_class_ai.positioning import (
    canonical_claim_language,
    rejected_claim_reasons,
)

_ROOT = Path(__file__).resolve().parent.parent


def _normalise(text: str) -> str:
    return " ".join(text.split())


def test_canonical_claim_language_defines_action_control_category() -> None:
    language = canonical_claim_language()

    assert language.primary_category == (
        "Runtime action-control and evidence layer for autonomous AI agents."
    )
    assert "prompt filter" in language.investor_summary
    assert "not another prompt filter" in language.investor_summary
    assert "local functional behaviour" in " ".join(language.allowed_claims)


def test_blocked_claim_detection_finds_forbidden_positioning() -> None:
    reasons = rejected_claim_reasons(
        "Director-Class AI is a generic prompt filter with benchmark advantage "
        "and production-ready kill-switch claims. It asserts counsel-reviewed "
        "evidence status and self-validating audit integrity."
    )

    assert len(reasons) == 5
    assert any("effector-bound action governance" in reason for reason in reasons)
    assert any("external artefacts" in reason for reason in reasons)
    assert any("deployment hardening" in reason for reason in reasons)
    assert any("counsel-reviewed" in reason for reason in reasons)
    assert any("independent integrity proof" in reason for reason in reasons)


def test_readme_uses_bounded_public_category() -> None:
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    language = canonical_claim_language()

    assert language.primary_category in readme
    assert language.public_summary in _normalise(readme)
    assert "production-ready kill-switch" not in readme
    assert "benchmark advantage" not in readme
    assert "generic prompt filter" not in readme


def test_public_claim_document_matches_canonical_language() -> None:
    claim_doc = (_ROOT / "docs" / "CLAIM_BOUNDARIES.md").read_text(encoding="utf-8")
    language = canonical_claim_language()

    assert language.public_markdown() in claim_doc
    assert language.demo_summary in claim_doc
    assert language.audit_integrity_boundary in claim_doc


def test_investor_markdown_renders_bounded_category() -> None:
    language = canonical_claim_language()
    markdown = language.investor_markdown()

    assert f"Category: {language.primary_category}" in markdown
    assert language.investor_summary in markdown
    assert "Defensible wedge:" in markdown
    assert "Blocked until evidence exists:" in markdown
