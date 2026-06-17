# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — capability policy tests

from __future__ import annotations

from director_class_ai.core import EvaluationRequest
from director_class_ai.policy import (
    CAPABILITY_CONTEXT_KEY,
    BlastRadius,
    CapabilityContext,
    CapabilityGrant,
    CapabilityPolicy,
    CapabilityPolicyDetector,
    OriginRule,
)


def _context(**overrides: object) -> CapabilityContext:
    base: dict[str, object] = {
        "subject": "agent-a",
        "tenant": "tenant-a",
        "session": "session-a",
        "source_origin": "user",
        "tool": "fs/read_file",
        "resource": "workspace:README.md",
        "action": "read",
        "blast_radius": "low",
        "now": 10,
    }
    base.update(overrides)
    return CapabilityContext.from_mapping(base)


def _grant(**overrides: object) -> CapabilityGrant:
    base: dict[str, object] = {
        "grant_id": "grant-read",
        "subject": "agent-a",
        "tenant": "tenant-a",
        "session": "session-a",
        "source_origin": "user",
        "tool": "fs/read_file",
        "resource": "workspace:README.md",
        "action": "read",
        "max_blast_radius": BlastRadius.LOW,
        "expires_at": 20,
    }
    base.update(overrides)
    return CapabilityGrant(**base)


def test_capability_policy_allows_matching_grant_and_origin_rule() -> None:
    policy = CapabilityPolicy(
        grants=(_grant(),),
        origin_rules=(OriginRule("user", tool="fs/read_file", action="read"),),
    )

    decision = policy.evaluate(_context())

    assert decision.permitted is True
    assert decision.requires_approval is False
    assert decision.matched_grant_ids == ("grant-read",)
    assert decision.audit_projection()["rationale"] == (
        "capability and origin policy matched"
    )


def test_capability_policy_denies_missing_grant_by_default() -> None:
    policy = CapabilityPolicy()

    decision = policy.evaluate(_context())

    assert decision.permitted is False
    assert decision.findings == ("capability_missing",)
    assert decision.matched_grant_ids == ()


def test_capability_policy_denies_disallowed_origin() -> None:
    policy = CapabilityPolicy(
        grants=(_grant(source_origin="retrieved"),),
        origin_rules=(OriginRule("user", tool="fs/read_file", action="read"),),
    )

    decision = policy.evaluate(_context(source_origin="retrieved"))

    assert decision.permitted is False
    assert "origin_not_allowed" in decision.findings


def test_capability_policy_denies_expired_or_excessive_blast_radius() -> None:
    expired = CapabilityPolicy(grants=(_grant(expires_at=5),))
    too_broad = CapabilityPolicy(grants=(_grant(max_blast_radius=BlastRadius.LOW),))

    assert expired.evaluate(_context(now=10)).findings == ("capability_missing",)
    assert too_broad.evaluate(_context(blast_radius="high")).findings == (
        "capability_missing",
    )


def test_capability_policy_routes_approval_required_grant() -> None:
    policy = CapabilityPolicy(grants=(_grant(approval_required=True),))

    decision = policy.evaluate(_context())

    assert decision.permitted is False
    assert decision.requires_approval is True
    assert decision.findings == ("approval_required",)


def test_capability_context_validates_required_fields_and_redacts_resource() -> None:
    context = _context(subject="", resource="workspace:private.txt")
    policy = CapabilityPolicy(grants=(_grant(),))

    decision = policy.evaluate(context)
    summary = context.redacted_summary()

    assert "missing_subject" in decision.findings
    assert summary["resource_present"] is True
    assert "private" not in repr(summary)


def test_capability_context_normalises_malformed_runtime_values() -> None:
    bool_time = CapabilityContext.from_mapping({"now": True})
    enum_radius = CapabilityContext.from_mapping({"blast_radius": BlastRadius.MEDIUM})
    unknown_radius = CapabilityContext.from_mapping({"blast_radius": "unknown"})
    invalid_radius = CapabilityContext.from_mapping({"blast_radius": 99})

    assert bool_time.now == 0
    assert enum_radius.blast_radius is BlastRadius.MEDIUM
    assert unknown_radius.blast_radius is BlastRadius.LOW
    assert invalid_radius.blast_radius is BlastRadius.CRITICAL


def test_capability_detector_blocks_missing_runtime_context() -> None:
    detector = CapabilityPolicyDetector(CapabilityPolicy(grants=(_grant(),)))

    signal = detector.evaluate(EvaluationRequest(action="fs/read_file"))

    assert signal is not None
    assert signal.signal_type == "capability_context_missing"


def test_capability_detector_blocks_unmatched_full_context() -> None:
    detector = CapabilityPolicyDetector(
        CapabilityPolicy(grants=(_grant(resource="workspace:other.md"),))
    )
    request = EvaluationRequest(
        action="fs/read_file",
        metadata={
            CAPABILITY_CONTEXT_KEY: {
                "subject": "agent-a",
                "tenant": "tenant-a",
                "session": "session-a",
                "source_origin": "user",
                "tool": "fs/read_file",
                "resource": "workspace:README.md",
                "action": "read",
                "blast_radius": "low",
                "now": 10,
            }
        },
    )

    signal = detector.evaluate(request)

    assert signal is not None
    assert signal.signal_type == "capability_missing"


def test_capability_detector_allows_matching_context() -> None:
    detector = CapabilityPolicyDetector(CapabilityPolicy(grants=(_grant(),)))
    request = EvaluationRequest(
        action="fs/read_file",
        metadata={
            CAPABILITY_CONTEXT_KEY: {
                "subject": "agent-a",
                "tenant": "tenant-a",
                "session": "session-a",
                "source_origin": "user",
                "tool": "fs/read_file",
                "resource": "workspace:README.md",
                "action": "read",
                "blast_radius": "low",
                "now": 10,
            }
        },
    )

    signal = detector.evaluate(request)

    assert signal is None


def test_capability_detector_rejects_redacted_summary_as_context() -> None:
    detector = CapabilityPolicyDetector(CapabilityPolicy(grants=(_grant(),)))
    request = EvaluationRequest(
        action="fs/read_file",
        metadata={CAPABILITY_CONTEXT_KEY: _context().redacted_summary()},
    )

    signal = detector.evaluate(request)

    assert signal is not None
    assert signal.signal_type == "capability_context_missing"


def test_capability_detector_escalates_approval_required_context() -> None:
    detector = CapabilityPolicyDetector(
        CapabilityPolicy(grants=(_grant(approval_required=True),))
    )
    request = EvaluationRequest(
        action="fs/read_file",
        metadata={
            CAPABILITY_CONTEXT_KEY: {
                "subject": "agent-a",
                "tenant": "tenant-a",
                "session": "session-a",
                "source_origin": "user",
                "tool": "fs/read_file",
                "resource": "workspace:README.md",
                "action": "read",
                "blast_radius": 1,
                "now": "10",
            }
        },
    )

    signal = detector.evaluate(request)

    assert signal is not None
    assert signal.signal_type == "capability_approval_required"
