# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — capability and origin policy compiler

"""Capability and origin policy for execution-time agent authorization.

The policy compiler separates *what a user can access* from *what an agent may
do at runtime*. A broad user credential does not automatically grant an agent
permission to mutate a resource. Every governed action can carry a
``CapabilityContext`` that names the subject, tenant, session, source origin,
tool, resource, action verb, blast radius, and current time. ``CapabilityPolicy``
then evaluates that context against data-only grants and origin rules.

The model is intentionally deterministic:

* grants are exact-or-wildcard records with expiry and optional approval
  requirements;
* origin rules state which source origins may influence which tool/resource/action
  classes;
* evaluation returns stable finding codes and a redacted rationale suitable for
  audit events;
* ``CapabilityPolicyDetector`` adapts the policy to the existing action-plane
  detector protocol, so gateways can compose it with registry, taint, destructive
  command, blast-radius, and approval routing without a second decision path.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum

from ..core import DetectorSignal, EvaluationRequest, Locus, Plane, Severity

__all__ = [
    "CAPABILITY_CONTEXT_KEY",
    "BlastRadius",
    "CapabilityContext",
    "CapabilityGrant",
    "CapabilityPolicy",
    "CapabilityPolicyDecision",
    "CapabilityPolicyDetector",
    "OriginRule",
]

CAPABILITY_CONTEXT_KEY = "capability_context"


class BlastRadius(IntEnum):
    """Ordered blast-radius levels used by capability grants."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class CapabilityContext:
    """Runtime action facts checked against capability and origin policy."""

    subject: str
    tenant: str
    session: str
    source_origin: str
    tool: str
    resource: str
    action: str
    blast_radius: BlastRadius = BlastRadius.LOW
    now: int = 0

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> CapabilityContext:
        """Build a context from JSON-like service or gateway metadata."""
        return cls(
            subject=_string(value.get("subject")),
            tenant=_string(value.get("tenant")),
            session=_string(value.get("session")),
            source_origin=_string(value.get("source_origin")),
            tool=_string(value.get("tool")),
            resource=_string(value.get("resource")),
            action=_string(value.get("action")),
            blast_radius=_blast_radius(value.get("blast_radius")),
            now=_integer(value.get("now")),
        )

    def redacted_summary(self) -> Mapping[str, object]:
        """Return field presence and classes without raw resource values."""
        return {
            "subject_present": bool(self.subject),
            "tenant": self.tenant,
            "session_present": bool(self.session),
            "source_origin": self.source_origin,
            "tool": self.tool,
            "action": self.action,
            "blast_radius": self.blast_radius.name.lower(),
            "resource_present": bool(self.resource),
        }


@dataclass(frozen=True)
class CapabilityGrant:
    """One data-only permission grant for an agent runtime action."""

    grant_id: str
    subject: str = "*"
    tenant: str = "*"
    session: str = "*"
    source_origin: str = "*"
    tool: str = "*"
    resource: str = "*"
    action: str = "*"
    max_blast_radius: BlastRadius = BlastRadius.LOW
    expires_at: int = 0
    approval_required: bool = False

    def matches(self, context: CapabilityContext) -> bool:
        """Return whether this grant covers the supplied runtime context."""
        if self.expires_at and context.now and context.now > self.expires_at:
            return False
        return (
            _matches(self.subject, context.subject)
            and _matches(self.tenant, context.tenant)
            and _matches(self.session, context.session)
            and _matches(self.source_origin, context.source_origin)
            and _matches(self.tool, context.tool)
            and _matches(self.resource, context.resource)
            and _matches(self.action, context.action)
            and context.blast_radius <= self.max_blast_radius
        )


@dataclass(frozen=True)
class OriginRule:
    """Allow one source-origin class to influence an action class."""

    source_origin: str
    tool: str = "*"
    resource: str = "*"
    action: str = "*"

    def allows(self, context: CapabilityContext) -> bool:
        """Return whether this rule permits the context's source influence."""
        return (
            _matches(self.source_origin, context.source_origin)
            and _matches(self.tool, context.tool)
            and _matches(self.resource, context.resource)
            and _matches(self.action, context.action)
        )


@dataclass(frozen=True)
class CapabilityPolicyDecision:
    """Redacted capability-policy outcome for detectors and audit events."""

    permitted: bool
    requires_approval: bool
    findings: tuple[str, ...]
    matched_grant_ids: tuple[str, ...]
    rationale: str

    def audit_projection(self) -> Mapping[str, object]:
        """Return policy evidence without raw subject, session, or resource data."""
        return {
            "permitted": self.permitted,
            "requires_approval": self.requires_approval,
            "findings": self.findings,
            "matched_grant_ids": self.matched_grant_ids,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class CapabilityPolicy:
    """Deny-by-default capability and origin policy."""

    grants: tuple[CapabilityGrant, ...] = ()
    origin_rules: tuple[OriginRule, ...] = ()

    def evaluate(self, context: CapabilityContext) -> CapabilityPolicyDecision:
        """Evaluate runtime context against grants and origin rules."""
        findings: list[str] = []

        missing = _missing_context_fields(context)
        if missing:
            return CapabilityPolicyDecision(
                permitted=False,
                requires_approval=False,
                findings=tuple(f"missing_{field}" for field in missing),
                matched_grant_ids=(),
                rationale="capability context missing required fields",
            )

        if self.origin_rules and not any(
            rule.allows(context) for rule in self.origin_rules
        ):
            findings.append("origin_not_allowed")

        matched = tuple(grant for grant in self.grants if grant.matches(context))
        if not matched:
            findings.append("capability_missing")

        if findings:
            return CapabilityPolicyDecision(
                permitted=False,
                requires_approval=False,
                findings=tuple(dict.fromkeys(findings)),
                matched_grant_ids=tuple(grant.grant_id for grant in matched),
                rationale="capability policy denied the action",
            )

        approval = any(grant.approval_required for grant in matched)
        return CapabilityPolicyDecision(
            permitted=not approval,
            requires_approval=approval,
            findings=("approval_required",) if approval else (),
            matched_grant_ids=tuple(grant.grant_id for grant in matched),
            rationale=(
                "capability grant requires human approval"
                if approval
                else "capability and origin policy matched"
            ),
        )


@dataclass
class CapabilityPolicyDetector:
    """Action-plane detector adapter for ``CapabilityPolicy``."""

    policy: CapabilityPolicy
    name: str = "capability_policy"
    plane: Plane = Plane.ACTION
    tier: int = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Return a policy signal when context is absent, denied, or escalated."""
        raw = request.metadata.get(CAPABILITY_CONTEXT_KEY)
        if not isinstance(raw, Mapping):
            return _signal(
                "capability_context_missing",
                Severity.HIGH,
                "capability policy is wired but runtime context is missing",
            )

        decision = self.policy.evaluate(CapabilityContext.from_mapping(raw))
        if decision.permitted:
            return None
        if decision.requires_approval:
            return _signal(
                "capability_approval_required",
                Severity.HIGH,
                decision.rationale,
            )
        if any(finding.startswith("missing_") for finding in decision.findings):
            signal_type = "capability_context_missing"
        elif "origin_not_allowed" in decision.findings:
            signal_type = "capability_origin_denied"
        else:
            signal_type = "capability_missing"
        return _signal(signal_type, Severity.HIGH, decision.rationale)


def _signal(
    signal_type: str,
    severity: Severity,
    rationale: str,
) -> DetectorSignal:
    return DetectorSignal(
        detector="capability_policy",
        plane=Plane.ACTION,
        score=0.9,
        locus=Locus.ACTION,
        signal_type=signal_type,
        severity=severity,
        rationale=rationale,
    )


def _missing_context_fields(context: CapabilityContext) -> tuple[str, ...]:
    values = {
        "subject": context.subject,
        "tenant": context.tenant,
        "session": context.session,
        "source_origin": context.source_origin,
        "tool": context.tool,
        "resource": context.resource,
        "action": context.action,
    }
    return tuple(name for name, value in values.items() if not value)


def _matches(pattern: str, value: str) -> bool:
    return pattern == "*" or pattern == value


def _string(value: object) -> str:
    return "" if value is None else str(value)


def _integer(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0


def _blast_radius(value: object) -> BlastRadius:
    if isinstance(value, BlastRadius):
        return value
    if isinstance(value, str):
        normalised = value.strip().upper()
        if normalised in BlastRadius.__members__:
            return BlastRadius[normalised]
    if isinstance(value, int):
        try:
            return BlastRadius(value)
        except ValueError:
            return BlastRadius.CRITICAL
    return BlastRadius.LOW
