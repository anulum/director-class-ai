# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — reversibility detector tests

from __future__ import annotations

from director_class_ai.action.reversibility import ReversibilityDetector
from director_class_ai.core import EvaluationRequest, Severity
from director_class_ai.effectors import ReversibilityMetadata

DET = ReversibilityDetector()


def test_empty_action_is_ignored() -> None:
    assert DET.evaluate(EvaluationRequest(action="   ")) is None


def test_read_only_action_is_ignored() -> None:
    assert DET.evaluate(EvaluationRequest(action="SELECT * FROM orders;")) is None


def test_irreversible_mutation_without_rollback_is_high() -> None:
    sig = DET.evaluate(EvaluationRequest(action="DROP TABLE orders;"))
    assert sig is not None
    assert sig.signal_type == "missing_reversibility"
    assert sig.severity is Severity.HIGH
    assert "rollback" in sig.rationale


def test_catastrophic_delete_without_snapshot_is_critical() -> None:
    sig = DET.evaluate(EvaluationRequest(action="rm -rf /"))
    assert sig is not None
    assert sig.severity is Severity.CRITICAL


def test_catastrophic_database_drop_without_snapshot_is_critical() -> None:
    sig = DET.evaluate(EvaluationRequest(action="DROP DATABASE production;"))
    assert sig is not None
    assert sig.severity is Severity.CRITICAL


def test_complete_reversibility_metadata_clears_project_local_cleanup() -> None:
    metadata = ReversibilityMetadata(
        snapshot_id="snap-build-20260617",
        rollback_command="restore ./build from snap-build-20260617",
        transaction_id="txn-build-clean",
        dry_run_digest="2d711642b726b044",
        diff_digest="9cdb1f24d346aa61",
    )
    req = EvaluationRequest(
        action="rm -rf ./build",
        metadata={"reversibility": metadata.to_metadata()},
    )
    assert DET.evaluate(req) is None


def test_complete_metadata_with_diff_digest_clears_irreversible_sql() -> None:
    metadata = ReversibilityMetadata(
        snapshot_id="snap-db-20260617",
        rollback_command="psql < rollback.sql",
        transaction_id="txn-db-drop",
        diff_digest="9cdb1f24d346aa61",
    )
    req = EvaluationRequest(
        action="DROP TABLE orders;",
        metadata={"reversibility": metadata.to_metadata()},
    )
    assert DET.evaluate(req) is None


def test_missing_diff_or_dry_run_digest_is_high() -> None:
    metadata = ReversibilityMetadata(
        snapshot_id="snap-db-20260617",
        rollback_command="psql < rollback.sql",
        transaction_id="txn-db-drop",
    )
    sig = DET.evaluate(
        EvaluationRequest(
            action="DROP TABLE orders;",
            metadata={"reversibility": metadata.to_metadata()},
        )
    )
    assert sig is not None
    assert sig.severity is Severity.HIGH
    assert "dry-run/diff" in sig.rationale


def test_non_mapping_reversibility_metadata_is_treated_as_absent() -> None:
    sig = DET.evaluate(
        EvaluationRequest(
            action="rm -rf ./build",
            metadata={"reversibility": "snap-build-20260617"},
        )
    )
    assert sig is not None
    assert "rollback evidence" in sig.rationale


def test_raw_diff_metadata_is_rejected() -> None:
    metadata = {
        "snapshot_id": "snap-build-20260617",
        "rollback_command": "restore ./build",
        "transaction_id": "txn-build-clean",
        "dry_run_digest": "2d711642b726b044",
        "diff_digest": "9cdb1f24d346aa61",
        "diff": "-old\n+new",
    }
    sig = DET.evaluate(
        EvaluationRequest(action="rm -rf ./build", metadata={"reversibility": metadata})
    )
    assert sig is not None
    assert sig.signal_type == "raw_reversibility_artifact"
    assert sig.severity is Severity.HIGH
