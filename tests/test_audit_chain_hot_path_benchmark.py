# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — audit-chain hot-path benchmark tests

from __future__ import annotations

import json

from benchmarks.audit_chain_hot_path import main, run_audit_chain_hot_path
from director_class_ai.audit import verify_chain


def test_audit_chain_hot_path_runs_real_sink_and_verifies(tmp_path) -> None:
    audit_path = tmp_path / "audit.jsonl"

    result = run_audit_chain_hot_path(audit_path, appends=8)

    assert result["benchmark"] == "audit_chain_hot_path"
    assert result["evidence_grade"] == "local-functional-non-isolated"
    assert "not an isolated throughput" in str(result["claim_boundary"])
    assert result["verification_ok"] is True
    assert audit_path.read_text(encoding="utf-8").count("\n") == 8
    assert verify_chain(audit_path).ok is True


def test_audit_chain_hot_path_cli_writes_bounded_result(tmp_path) -> None:
    output = tmp_path / "audit_hot_path.json"

    assert main(["--appends", "3", "--output", str(output)]) == 0

    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["appends"] == 3
    assert saved["verification_ok"] is True
    assert saved["hot_path"] == "AuditChainSink append with in-process locked head cache"
