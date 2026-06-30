# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — evidence package tests

from __future__ import annotations

import json
from pathlib import Path

from director_class_ai.action import DestructiveCommandDetector, OriginTaintDetector
from director_class_ai.audit import AuditChainSink
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Governor,
    Locus,
    ParallelEnsembleScorer,
    Plane,
    Severity,
)
from director_class_ai.core.fusion import Verdict
from director_class_ai.core.governor import AuditRecord, Decision
from director_class_ai.evidence import (
    ControlMapping,
    EvidencePackage,
    HashChainProof,
    IncidentReplayFixture,
    ProvenanceEdge,
    build_evidence_package,
    hash_chain_proof_for_digest,
    replay_incident,
)
from tests._payloads import rows, section, text


class _Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        self.t += 1.0
        return self.t


def _governor(path: Path) -> Governor:
    return Governor(
        ensemble=ParallelEnsembleScorer([DestructiveCommandDetector()]),
        audit_sink=AuditChainSink(path=path, policy_profile="pilot", clock=_Clock()),
    )


def _manual_decision(
    *,
    permitted: bool,
    escalated: bool,
    requires_human: bool,
) -> Decision:
    signal = DetectorSignal(
        detector="manual",
        plane=Plane.ACTION,
        score=0.4,
        locus=Locus.ACTION,
        signal_type="mcp_remote_auth",
        severity=Severity.HIGH,
        rationale="raw rationale kept out of evidence",
    )
    verdict = Verdict(
        allow=permitted or requires_human,
        risk=0.4,
        requires_human=requires_human,
        firing=(signal,),
        rationale="manual fixture",
    )
    record = AuditRecord(
        permitted=permitted,
        escalated=escalated,
        risk=0.4,
        requires_human=requires_human,
        rationale="manual fixture",
        firing=("mcp_remote_auth",),
        request_digest="manual-digest",
    )
    return Decision(
        permitted=permitted,
        escalated=escalated,
        verdict=verdict,
        record=record,
    )


def test_evidence_package_is_redacted_and_chain_bound(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    request = EvaluationRequest(query="clean", action="rm -rf /private")
    decision = _governor(audit_path).review(request)
    proof = hash_chain_proof_for_digest(audit_path, decision.record.request_digest)

    package = build_evidence_package(
        decision,
        policy_profile="pilot",
        provenance_graph=(
            ProvenanceEdge(
                source="user",
                target="shell",
                relation="requested_action",
                source_digest="src-digest",
                target_digest=decision.record.request_digest,
            ),
        ),
        benchmark_replay_id="action-plane-functional-2026-06-18",
        hash_chain_proof=proof,
    )
    payload = package.to_json()
    rendered = json.dumps(payload, sort_keys=True)

    assert payload["request_digest"] == decision.record.request_digest
    assert payload["policy_profile"] == "pilot"
    assert payload["action_route"] == "block"
    assert payload["approval_state"] == "blocked"
    assert section(payload, "hash_chain_proof")["verified"] is True
    assert section(payload, "hash_chain_proof")["entry_hash"]
    assert payload["benchmark_replay_id"] == "action-plane-functional-2026-06-18"
    assert payload["evidence_digest"] == package.evidence_digest
    assert "destructive_command" in rendered
    tags = rows(payload, "technique_tags")
    assert any(tag["technique_id"] == "AML.T0050" for tag in tags)
    assert all("does not" in text(tag, "claim_boundary") for tag in tags)
    assert "rm -rf" not in rendered
    assert "private" not in rendered


def test_evidence_package_includes_capability_grants_and_controls(
    tmp_path: Path,
) -> None:
    decision = _governor(tmp_path / "audit.jsonl").review(
        EvaluationRequest(action="rm -rf /")
    )
    projection = {
        "summary": {"tool": "shell", "resource_present": True},
        "decision": {
            "matched_grant_ids": ("grant-prod-shell",),
            "findings": ("approval_required",),
        },
    }

    package = build_evidence_package(
        decision,
        policy_profile="high_risk",
        capability_projection=projection,
    )
    payload = package.to_json()

    assert payload["capability_grant_ids"] == ["grant-prod-shell"]
    controls = rows(payload, "controls")
    assert any(
        control["framework"] == "NIST AI RMF / GenAI profile" for control in controls
    )
    assert any(control["framework"] == "OWASP LLM risks" for control in controls)
    assert any(control["framework"] == "Buyer control taxonomy" for control in controls)
    assert all("does not" in text(control, "claim_boundary") for control in controls)
    assert any(tag["technique_id"] == "ASI09" for tag in rows(payload, "technique_tags"))


def test_evidence_package_accepts_mapping_edges_and_existing_digest() -> None:
    package = EvidencePackage(
        request_digest="digest",
        policy_profile="pilot",
        action_route="allow",
        approval_state="permitted",
        detector_signals=(),
        provenance_graph=(
            ProvenanceEdge.from_mapping(
                {
                    "source": "operator",
                    "target": "shell",
                    "relation": "reviewed",
                    "source_digest": "src",
                    "target_digest": "dst",
                }
            ),
        ),
        hash_chain_proof=HashChainProof(verified=False, reason="not_supplied"),
        controls=(
            ControlMapping(
                framework="Buyer control taxonomy",
                control_id="manual",
                control_name="Manual review",
                finding="allow",
                claim_boundary="Records review; does not assert certification.",
            ),
        ),
        evidence_digest="existing-digest",
    )
    payload = package.to_json()

    assert payload["evidence_digest"] == "existing-digest"
    assert rows(payload, "provenance_graph")[0]["source"] == "operator"
    assert rows(payload, "controls")[0]["control_id"] == "manual"
    assert payload["technique_tags"] == []


def test_manual_decision_routes_cover_allow_and_approved_human() -> None:
    allowed = build_evidence_package(
        _manual_decision(permitted=True, escalated=False, requires_human=False),
        policy_profile="pilot",
        provenance_graph=({"source": "user", "target": "shell", "relation": "allow"},),
    )
    approved = build_evidence_package(
        _manual_decision(permitted=True, escalated=True, requires_human=True),
        policy_profile="pilot",
    )

    assert allowed.to_json()["action_route"] == "allow"
    assert allowed.to_json()["approval_state"] == "permitted"
    assert approved.to_json()["action_route"] == "allow"
    assert approved.to_json()["approval_state"] == "approved"
    assert any(
        control["framework"] == "MCP security considerations"
        for control in rows(approved.to_json(), "controls")
    )


def test_manual_pending_human_decision_records_pending_state() -> None:
    pending = build_evidence_package(
        _manual_decision(permitted=False, escalated=True, requires_human=True),
        policy_profile="pilot",
    )
    payload = pending.to_json()

    assert payload["action_route"] == "human"
    assert payload["approval_state"] == "denied_or_pending"
    assert any(
        tag["technique_id"] == "AML.T0061" for tag in rows(payload, "technique_tags")
    )


def test_malformed_capability_projection_defaults_empty(tmp_path: Path) -> None:
    decision = _governor(tmp_path / "audit.jsonl").review(
        EvaluationRequest(action="rm -rf /")
    )

    package = build_evidence_package(
        decision,
        policy_profile="pilot",
        capability_projection={"decision": "not-a-mapping"},
    )

    assert package.to_json()["capability_grant_ids"] == []


def test_scalar_capability_projection_fields_default_empty(tmp_path: Path) -> None:
    decision = _governor(tmp_path / "audit.jsonl").review(
        EvaluationRequest(action="rm -rf /")
    )

    package = build_evidence_package(
        decision,
        policy_profile="pilot",
        capability_projection={
            "decision": {
                "matched_grant_ids": "grant-id",
                "findings": "approval_required",
            }
        },
    )

    assert package.to_json()["capability_grant_ids"] == []


def test_hash_chain_proof_reports_missing_and_tampered_chain(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    decision = _governor(audit_path).review(EvaluationRequest(action="rm -rf /"))

    missing = hash_chain_proof_for_digest(audit_path, "missing")
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["risk"] = 0.0
    audit_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
    broken = hash_chain_proof_for_digest(audit_path, decision.record.request_digest)

    assert missing.verified is False
    assert missing.reason == "request_digest_not_found"
    assert broken.verified is False
    assert "mismatch" in broken.reason


def test_hash_chain_proof_tolerates_blank_lines(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    decision = _governor(audit_path).review(EvaluationRequest(action="ls"))
    audit_path.write_text(
        audit_path.read_text(encoding="utf-8") + "\n\n",
        encoding="utf-8",
    )

    proof = hash_chain_proof_for_digest(audit_path, decision.record.request_digest)

    assert proof.verified is True


def test_incident_replay_uses_sanitized_fixture_without_raw_output() -> None:
    fixture = IncidentReplayFixture(
        fixture_id="replay-001",
        request=EvaluationRequest(
            query="sanitized cleanup request",
            action="rm -rf /sanitized",
            action_provenance="user",
        ),
        expected_route="block",
        source_evidence_digest="evidence-digest",
        notes="curated local fixture",
    )

    result = replay_incident(
        fixture,
        ParallelEnsembleScorer([DestructiveCommandDetector()]),
    )
    payload = result.to_json()
    rendered = json.dumps(payload, sort_keys=True)

    assert payload["fixture_id"] == "replay-001"
    assert payload["expected_route"] == "block"
    assert payload["observed_route"] == "block"
    assert payload["route_conformant"] is True
    assert payload["fixture_digest"] == fixture.fixture_digest()
    assert "destructive_command" in rendered
    assert "rm -rf" not in rendered
    assert "sanitized" not in rendered


def test_incident_replay_covers_allow_and_block_routes() -> None:
    ensemble = ParallelEnsembleScorer([DestructiveCommandDetector()])
    allowed = replay_incident(
        IncidentReplayFixture(
            fixture_id="allow",
            request=EvaluationRequest(action="ls", action_provenance="user"),
            expected_route="allow",
            source_evidence_digest="source",
        ),
        ensemble,
    )
    blocked = replay_incident(
        IncidentReplayFixture(
            fixture_id="block",
            request=EvaluationRequest(
                action="deploy production",
                action_provenance="retrieved",
            ),
            expected_route="block",
            source_evidence_digest="source",
        ),
        ParallelEnsembleScorer([OriginTaintDetector()]),
    )

    assert allowed.observed_route == "allow"
    assert allowed.route_conformant is True
    assert blocked.observed_route == "block"
    assert blocked.route_conformant is True


def test_incident_replay_covers_human_route() -> None:
    class _HumanDetector:
        name = "human_detector"
        plane = Plane.ACTION
        tier = 0

        def evaluate(self, request: EvaluationRequest) -> DetectorSignal:
            return DetectorSignal(
                detector=self.name,
                plane=Plane.ACTION,
                score=0.2,
                locus=Locus.ACTION,
                signal_type="manual_review",
                severity=Severity.MEDIUM,
            )

    result = replay_incident(
        IncidentReplayFixture(
            fixture_id="human",
            request=EvaluationRequest(action="chmod -R 777 /srv"),
            expected_route="human",
            source_evidence_digest="source",
        ),
        ParallelEnsembleScorer([_HumanDetector()]),
    )

    assert result.observed_route == "human"
    assert result.route_conformant is True
