# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — redacted evidence packages

"""Decision evidence packages for audit, compliance, and incident response.

The package deliberately stores identifiers, digests, route decisions, detector
codes, policy findings, and bounded control mappings. It does not store raw
prompt text, command text, tool output, browser text, resource names, subject
names, or session identifiers. Incident replay uses separately curated sanitized
fixtures, so responders can reproduce the control path without exposing private
production material.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from ..audit import verify_chain
from ..core import EvaluationRequest, ParallelEnsembleScorer
from ..core.governor import Decision, digest_request
from ..core.signal import DetectorSignal

__all__ = [
    "ControlMapping",
    "DetectorEvidence",
    "EvidencePackage",
    "HashChainProof",
    "IncidentReplayFixture",
    "IncidentReplayResult",
    "ProvenanceEdge",
    "build_evidence_package",
    "hash_chain_proof_for_digest",
    "replay_incident",
]

ActionRoute = Literal["allow", "human", "block"]
ApprovalState = Literal["permitted", "approved", "denied_or_pending", "blocked"]

_SCHEMA_VERSION = "director-class-ai.evidence.v1"


@dataclass(frozen=True)
class DetectorEvidence:
    """Redacted detector firing included in a decision evidence package."""

    detector: str
    plane: str
    signal_type: str
    severity: str
    score: float
    calibration: float
    weighted_score: float
    rationale_digest: str = ""

    @classmethod
    def from_signal(cls, signal: DetectorSignal) -> DetectorEvidence:
        """Build redacted detector evidence from a detector signal."""
        return cls(
            detector=signal.detector,
            plane=signal.plane.value,
            signal_type=signal.signal_type,
            severity=signal.severity.name.lower(),
            score=signal.score,
            calibration=signal.calibration,
            weighted_score=signal.weighted_score,
            rationale_digest=_digest(signal.rationale),
        )

    def to_json(self) -> dict[str, object]:
        """Return a deterministic JSON-ready detector evidence object."""
        return {
            "detector": self.detector,
            "plane": self.plane,
            "signal_type": self.signal_type,
            "severity": self.severity,
            "score": self.score,
            "calibration": self.calibration,
            "weighted_score": self.weighted_score,
            "rationale_digest": self.rationale_digest,
        }


@dataclass(frozen=True)
class ProvenanceEdge:
    """Redacted provenance relation for an action-control decision."""

    source: str
    target: str
    relation: str
    source_digest: str = ""
    target_digest: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> ProvenanceEdge:
        """Parse a JSON-like redacted provenance edge."""
        return cls(
            source=_string(value.get("source")),
            target=_string(value.get("target")),
            relation=_string(value.get("relation")),
            source_digest=_string(value.get("source_digest")),
            target_digest=_string(value.get("target_digest")),
        )

    def to_json(self) -> dict[str, object]:
        """Return a deterministic JSON-ready provenance relation."""
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
        }


@dataclass(frozen=True)
class HashChainProof:
    """Tamper-evident chain position for the audit entry behind a decision."""

    verified: bool
    chain_sequence: int | None = None
    entry_hash: str = ""
    prev_hash: str = ""
    reason: str = ""

    def to_json(self) -> dict[str, object]:
        """Return JSON-ready hash-chain proof fields."""
        return {
            "verified": self.verified,
            "chain_sequence": self.chain_sequence,
            "entry_hash": self.entry_hash,
            "prev_hash": self.prev_hash,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ControlMapping:
    """Bounded compliance/control mapping for a detector or route finding."""

    framework: str
    control_id: str
    control_name: str
    finding: str
    claim_boundary: str

    def to_json(self) -> dict[str, str]:
        """Return JSON-ready control mapping fields."""
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "finding": self.finding,
            "claim_boundary": self.claim_boundary,
        }


@dataclass(frozen=True)
class EvidencePackage:
    """Auditor-facing evidence package for one governed decision."""

    request_digest: str
    policy_profile: str
    action_route: ActionRoute
    approval_state: ApprovalState
    detector_signals: tuple[DetectorEvidence, ...]
    capability_grant_ids: tuple[str, ...] = ()
    provenance_graph: tuple[ProvenanceEdge, ...] = ()
    benchmark_replay_id: str = ""
    hash_chain_proof: HashChainProof = field(
        default_factory=lambda: HashChainProof(verified=False, reason="not_supplied")
    )
    controls: tuple[ControlMapping, ...] = ()
    evidence_digest: str = ""

    def __post_init__(self) -> None:
        """Populate the evidence digest from the redacted package payload."""
        if not self.evidence_digest:
            object.__setattr__(self, "evidence_digest", _digest_json(self._payload()))

    def to_json(self) -> dict[str, object]:
        """Return the stable redacted evidence package object."""
        payload = self._payload()
        payload["evidence_digest"] = self.evidence_digest
        return payload

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "request_digest": self.request_digest,
            "policy_profile": self.policy_profile,
            "action_route": self.action_route,
            "approval_state": self.approval_state,
            "detector_signals": [signal.to_json() for signal in self.detector_signals],
            "capability_grant_ids": list(self.capability_grant_ids),
            "provenance_graph": [edge.to_json() for edge in self.provenance_graph],
            "benchmark_replay_id": self.benchmark_replay_id,
            "hash_chain_proof": self.hash_chain_proof.to_json(),
            "controls": [control.to_json() for control in self.controls],
        }


@dataclass(frozen=True)
class IncidentReplayFixture:
    """Sanitized request fixture used to replay a historical decision path."""

    fixture_id: str
    request: EvaluationRequest
    expected_route: ActionRoute
    source_evidence_digest: str
    notes: str = ""

    def fixture_digest(self) -> str:
        """Return the digest of the sanitized replay fixture."""
        payload = {
            "fixture_id": self.fixture_id,
            "query": self.request.query,
            "response": self.request.response,
            "context": self.request.context,
            "action": self.request.action,
            "action_provenance": self.request.action_provenance,
            "tenant_id": self.request.tenant_id,
            "metadata_keys": sorted(self.request.metadata),
            "expected_route": self.expected_route,
            "source_evidence_digest": self.source_evidence_digest,
            "notes_digest": _digest(self.notes),
        }
        return _digest_json(payload)


@dataclass(frozen=True)
class IncidentReplayResult:
    """Result of replaying one sanitized incident fixture."""

    fixture_id: str
    source_evidence_digest: str
    fixture_digest: str
    expected_route: ActionRoute
    observed_route: ActionRoute
    route_conformant: bool
    request_digest: str
    detector_signals: tuple[DetectorEvidence, ...]

    def to_json(self) -> dict[str, object]:
        """Return a redacted replay-result object."""
        return {
            "fixture_id": self.fixture_id,
            "source_evidence_digest": self.source_evidence_digest,
            "fixture_digest": self.fixture_digest,
            "expected_route": self.expected_route,
            "observed_route": self.observed_route,
            "route_conformant": self.route_conformant,
            "request_digest": self.request_digest,
            "detector_signals": [signal.to_json() for signal in self.detector_signals],
        }


def build_evidence_package(
    decision: Decision,
    *,
    policy_profile: str,
    capability_projection: Mapping[str, object] | None = None,
    provenance_graph: Sequence[ProvenanceEdge | Mapping[str, object]] = (),
    benchmark_replay_id: str = "",
    hash_chain_proof: HashChainProof | None = None,
) -> EvidencePackage:
    """Build one redacted evidence package from a governed decision."""
    detector_signals = tuple(
        DetectorEvidence.from_signal(signal) for signal in decision.verdict.firing
    )
    grants = _capability_grants(capability_projection)
    edges = tuple(_edge(edge) for edge in provenance_graph)
    controls = controls_for_decision(
        action_route=_route(decision),
        detector_signals=detector_signals,
        capability_findings=_capability_findings(capability_projection),
    )
    return EvidencePackage(
        request_digest=decision.record.request_digest,
        policy_profile=policy_profile,
        action_route=_route(decision),
        approval_state=_approval_state(decision),
        detector_signals=detector_signals,
        capability_grant_ids=grants,
        provenance_graph=edges,
        benchmark_replay_id=benchmark_replay_id,
        hash_chain_proof=hash_chain_proof
        or HashChainProof(verified=False, reason="not_supplied"),
        controls=controls,
    )


def hash_chain_proof_for_digest(path: str | Path, request_digest: str) -> HashChainProof:
    """Return the verified audit-chain proof for a request digest."""
    verification = verify_chain(path)
    if not verification.ok:
        return HashChainProof(verified=False, reason=verification.reason)
    for entry in _read_entries(Path(path)):
        if entry.get("request_digest") == request_digest:
            return HashChainProof(
                verified=True,
                chain_sequence=_optional_int(entry.get("seq")),
                entry_hash=_string(entry.get("entry_hash")),
                prev_hash=_string(entry.get("prev_hash")),
            )
    return HashChainProof(verified=False, reason="request_digest_not_found")


def controls_for_decision(
    *,
    action_route: ActionRoute,
    detector_signals: Sequence[DetectorEvidence],
    capability_findings: Sequence[str] = (),
) -> tuple[ControlMapping, ...]:
    """Map decision findings to bounded compliance and buyer-control language."""
    findings = {signal.signal_type for signal in detector_signals}
    findings.update(capability_findings)
    mappings: list[ControlMapping] = [
        ControlMapping(
            framework="NIST AI RMF / GenAI profile",
            control_id="GOVERN-MAP-MEASURE",
            control_name="Runtime action governance evidence",
            finding=f"route:{action_route}",
            claim_boundary=(
                "Documents runtime review evidence; does not assert certification."
            ),
        )
    ]
    if action_route in {"block", "human"}:
        mappings.append(
            ControlMapping(
                framework="OWASP LLM risks",
                control_id="LLM-agentic-action-control",
                control_name="High-impact action mediation",
                finding=f"route:{action_route}",
                claim_boundary=(
                    "Maps to agentic action risk controls; does not claim complete "
                    "prompt-injection prevention."
                ),
            )
        )
    has_capability_evidence = bool(capability_findings) or any(
        finding.startswith("capability_") or "capability" in finding
        for finding in findings
    )
    if has_capability_evidence:
        mappings.append(
            ControlMapping(
                framework="Buyer control taxonomy",
                control_id="capability-origin-boundary",
                control_name="Capability and origin authorization",
                finding="capability_policy",
                claim_boundary=(
                    "Shows deterministic grant/origin evaluation; does not expose "
                    "raw subject, session, or resource values."
                ),
            )
        )
    if any(finding.startswith("mcp_") for finding in findings):
        mappings.append(
            ControlMapping(
                framework="MCP security considerations",
                control_id="tool-registry-and-transport-binding",
                control_name="Tool-call trust and transport review",
                finding="mcp_review",
                claim_boundary=(
                    "Records MCP trust checks; does not certify a remote server."
                ),
            )
        )
    return tuple(mappings)


def replay_incident(
    fixture: IncidentReplayFixture,
    ensemble: ParallelEnsembleScorer,
) -> IncidentReplayResult:
    """Replay one sanitized incident fixture through the supplied ensemble."""
    verdict = ensemble.evaluate(fixture.request)
    route: ActionRoute
    if verdict.allow and not verdict.requires_human:
        route = "allow"
    elif verdict.requires_human:
        route = "human"
    else:
        route = "block"
    return IncidentReplayResult(
        fixture_id=fixture.fixture_id,
        source_evidence_digest=fixture.source_evidence_digest,
        fixture_digest=fixture.fixture_digest(),
        expected_route=fixture.expected_route,
        observed_route=route,
        route_conformant=route == fixture.expected_route,
        request_digest=digest_request(fixture.request),
        detector_signals=tuple(
            DetectorEvidence.from_signal(signal) for signal in verdict.firing
        ),
    )


def _route(decision: Decision) -> ActionRoute:
    if decision.permitted:
        return "allow"
    if decision.escalated or decision.record.requires_human:
        return "human"
    return "block"


def _approval_state(decision: Decision) -> ApprovalState:
    if decision.escalated:
        return "approved" if decision.permitted else "denied_or_pending"
    return "permitted" if decision.permitted else "blocked"


def _capability_grants(projection: Mapping[str, object] | None) -> tuple[str, ...]:
    if not projection:
        return ()
    decision = projection.get("decision")
    if not isinstance(decision, Mapping):
        return ()
    return tuple(_strings(decision.get("matched_grant_ids")))


def _capability_findings(projection: Mapping[str, object] | None) -> tuple[str, ...]:
    if not projection:
        return ()
    decision = projection.get("decision")
    if not isinstance(decision, Mapping):
        return ()
    return tuple(_strings(decision.get("findings")))


def _edge(value: ProvenanceEdge | Mapping[str, object]) -> ProvenanceEdge:
    if isinstance(value, ProvenanceEdge):
        return value
    return ProvenanceEdge.from_mapping(value)


def _read_entries(path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(cast(dict[str, object], json.loads(line)))
    return entries


def _digest(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _digest_json(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _strings(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return []
    return [item for item in value if isinstance(item, str)]
