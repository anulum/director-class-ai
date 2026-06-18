# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — bounded product positioning

"""Canonical bounded positioning for product, investor, and demo copy.

The repo uses this module as the single claim-language source of truth. It keeps
public README text, investor briefings, demo captions, and internal control
language aligned with the evidence that exists today: runtime action-control,
human escalation, audit/evidence records, and local functional benchmark data.
It also lists claims that remain blocked until isolated benchmarks, external
artefacts, deployment hardening, and certification work exist.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "BlockedClaim",
    "ClaimLanguage",
    "canonical_claim_language",
    "rejected_claim_reasons",
]


@dataclass(frozen=True)
class BlockedClaim:
    """Claim pattern that must not appear in public or investor copy."""

    pattern: str
    reason: str


@dataclass(frozen=True)
class ClaimLanguage:
    """Bounded claim language shared across public, investor, and demo surfaces."""

    primary_category: str
    public_summary: str
    investor_summary: str
    demo_summary: str
    allowed_claims: tuple[str, ...]
    blocked_claims: tuple[BlockedClaim, ...]
    benchmark_boundary: str
    certification_boundary: str
    prompt_injection_boundary: str

    def public_markdown(self) -> str:
        """Render public copy that stays inside the current evidence boundary."""
        return "\n".join(
            (
                f"Primary category: {self.primary_category}",
                "",
                self.public_summary,
                "",
                "Allowed claim language:",
                *[f"- {claim}" for claim in self.allowed_claims],
                "",
                f"Benchmark boundary: {self.benchmark_boundary}",
                f"Certification boundary: {self.certification_boundary}",
                f"Prompt-injection boundary: {self.prompt_injection_boundary}",
            )
        )

    def investor_markdown(self) -> str:
        """Render investor copy with the same bounded category and constraints."""
        blocked = [
            f"- Do not claim {claim.pattern}: {claim.reason}"
            for claim in self.blocked_claims
        ]
        return "\n".join(
            (
                f"Category: {self.primary_category}",
                "",
                self.investor_summary,
                "",
                "Defensible wedge:",
                *[f"- {claim}" for claim in self.allowed_claims],
                "",
                "Blocked until evidence exists:",
                *blocked,
            )
        )


def canonical_claim_language() -> ClaimLanguage:
    """Return the canonical bounded product-positioning language."""
    return ClaimLanguage(
        primary_category=(
            "Runtime action-control and evidence layer for autonomous AI agents."
        ),
        public_summary=(
            "Director-Class AI sits between an autonomous agent and its effectors. "
            "It reviews high-impact shell, SQL, infrastructure, API, and MCP tool "
            "actions before dispatch; uncertain or high-risk actions escalate to "
            "human approval and emit tamper-evident audit/evidence records."
        ),
        investor_summary=(
            "The product wedge is not another prompt filter. It is an effector-bound "
            "runtime checkpoint for agentic systems where mistakes can modify "
            "filesystems, databases, cloud resources, payments, identity, or other "
            "operational state. Content and prompt-injection detectors are supporting "
            "signals that feed action governance."
        ),
        demo_summary=(
            "This demo shows a governed action checkpoint: the proposed tool call is "
            "reviewed, routed to allow/block/human approval, and recorded as redacted "
            "audit evidence before any real executor can run."
        ),
        allowed_claims=(
            "Primary category is runtime action-control and evidence for "
            "autonomous agents.",
            "The action plane is the differentiator; prompt and content checks "
            "are supporting signals.",
            "Current evidence supports local functional behaviour, not public "
            "comparative benchmark claims.",
            "Audit, SIEM export, approval, and evidence packages are redacted "
            "and digest-bound.",
            "High-impact or uncertain actions can be blocked or escalated "
            "before execution.",
        ),
        blocked_claims=(
            BlockedClaim(
                pattern="generic prompt filter",
                reason="the product category is effector-bound action governance.",
            ),
            BlockedClaim(
                pattern="benchmark advantage",
                reason="isolated runs and external artefacts are still required.",
            ),
            BlockedClaim(
                pattern="production-ready kill-switch",
                reason="remote CI/protection and deployment hardening remain open.",
            ),
            BlockedClaim(
                pattern="certification readiness",
                reason="compliance mappings are bounded evidence, not certification.",
            ),
            BlockedClaim(
                pattern="100% prompt-injection prevention",
                reason=(
                    "prompt-injection checks are one signal, not a complete "
                    "prevention claim."
                ),
            ),
        ),
        benchmark_boundary=(
            "Use local functional benchmark evidence only; do not claim benchmark "
            "advantage until isolated host-load-controlled runs and external "
            "artefacts exist."
        ),
        certification_boundary=(
            "Control mappings support review and procurement discussion; they do not "
            "assert certification or regulatory approval."
        ),
        prompt_injection_boundary=(
            "Prompt-injection detection is a signal in the action-control path, not "
            "the product category and not a guarantee of full prevention."
        ),
    )


def rejected_claim_reasons(text: str) -> tuple[str, ...]:
    """Return blocked-claim reasons found in a candidate text surface."""
    normalized = " ".join(text.casefold().split())
    language = canonical_claim_language()
    return tuple(
        claim.reason
        for claim in language.blocked_claims
        if claim.pattern.casefold() in normalized
    )
