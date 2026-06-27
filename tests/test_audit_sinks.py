# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — audit export sink tests

from __future__ import annotations

import json
from pathlib import Path

import pytest

from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.audit import (
    AuditChainSink,
    audit_record_to_event,
    chain_entry_to_event,
    export_chain_to_siem_jsonl,
)
from director_class_ai.core import EvaluationRequest, Governor, ParallelEnsembleScorer
from director_class_ai.core.governor import AuditRecord


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


def _populate(path: Path) -> Governor:
    gov = _governor(path)
    gov.review(EvaluationRequest(query="inspect", action="ls -la"))
    gov.review(EvaluationRequest(query="inspect", action="rm -rf /"))
    return gov


def test_export_chain_to_siem_jsonl_verifies_and_strips_raw_action(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    _populate(path)

    exported = export_chain_to_siem_jsonl(path)
    events = [json.loads(line) for line in exported.splitlines()]

    assert len(events) == 2
    assert events[1]["event_name"] == "director_class_ai.governance.decision"
    assert events[1]["decision_id"]
    assert events[1]["detector_ids"] == ["destructive_command"]
    assert events[1]["technique_ids"] == ["ASI05", "AML.T0050"]
    assert {
        (tag["framework"], tag["technique_id"]) for tag in events[1]["technique_tags"]
    } == {("OWASP ASI", "ASI05"), ("MITRE ATLAS", "AML.T0050")}
    assert events[1]["policy_profile"] == "pilot"
    assert events[1]["approval_state"] == "blocked"
    assert events[1]["request_digest"]
    assert "rm -rf /" not in exported


def test_export_chain_to_siem_jsonl_can_require_signed_anchor(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    anchor = tmp_path / "anchor.jsonl"
    governor = Governor(
        ensemble=ParallelEnsembleScorer([DestructiveCommandDetector()]),
        audit_sink=AuditChainSink(
            path=path,
            policy_profile="pilot",
            clock=_Clock(),
            head_signing_key="sink-secret",
            anchor_path=anchor,
        ),
    )
    governor.review(EvaluationRequest(query="inspect", action="ls -la"))

    exported = export_chain_to_siem_jsonl(
        path, head_signing_key="sink-secret", anchor_path=anchor
    )

    assert len(exported.splitlines()) == 1


def test_export_can_write_jsonl_file(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    out = tmp_path / "siem.jsonl"
    _populate(path)

    returned = export_chain_to_siem_jsonl(path, out_path=out)

    assert returned == out.read_text(encoding="utf-8")
    assert len(out.read_text(encoding="utf-8").splitlines()) == 2


def test_export_tolerates_blank_lines_in_verified_chain(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    _populate(path)
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    exported = export_chain_to_siem_jsonl(path)

    assert len(exported.splitlines()) == 2


def test_export_rejects_unverified_chain(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    _populate(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["risk"] = 0.0
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="audit chain verification failed"):
        export_chain_to_siem_jsonl(path)


def test_live_audit_record_maps_to_otel_style_attributes(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    decision = _populate(path).trail[-1]

    event = audit_record_to_event(decision, policy_profile="pilot")
    attrs = event.to_otel_attributes()

    assert attrs["event.name"] == "director_class_ai.governance.decision"
    assert attrs["policy.profile"] == "pilot"
    assert attrs["approval.state"] == "blocked"
    assert attrs["request.digest"] == decision.request_digest
    assert attrs["detector.ids"] == ["destructive_command"]
    assert attrs["threat.technique.ids"] == ["ASI05", "AML.T0050"]
    assert attrs["threat.technique.names"] == [
        "Unexpected Code Execution",
        "Command and Scripting Interpreter",
    ]
    assert "rm -rf /" not in json.dumps(event.to_siem_json(), sort_keys=True)


def test_live_audit_record_approved_state_is_preserved() -> None:
    record = AuditRecord(
        permitted=True,
        escalated=True,
        risk=0.2,
        requires_human=True,
        rationale="approval consumed",
        firing=("border",),
        request_digest="abc123",
    )

    event = audit_record_to_event(record, policy_profile="pilot")

    assert event.approval_state == "approved"
    assert event.technique_ids == ()


def test_chain_entry_malformed_detector_list_defaults_empty() -> None:
    event = audit_record_to_event(
        AuditRecord(
            permitted=True,
            escalated=False,
            risk=0.0,
            requires_human=False,
            rationale="none",
            firing=(),
            request_digest="abc123",
        )
    )
    payload = event.to_siem_json()
    payload["entry_hash"] = "h"
    payload["created_at"] = 1.0
    payload["firing"] = "not-a-list"
    payload["seq"] = 7

    malformed = chain_entry_to_event(payload)

    assert malformed.detector_ids == ()
    assert malformed.technique_ids == ()
