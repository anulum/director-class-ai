# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — blast-radius / origin-taint / intent-consistency tests

from __future__ import annotations

from director_class_ai.action import (
    BlastRadiusDetector,
    IntentConsistencyDetector,
    OriginTaintDetector,
)
from director_class_ai.core import EvaluationRequest, Plane, Severity


class TestBlastRadius:
    det = BlastRadiusDetector()

    def test_irreversible_plus_production_is_high(self) -> None:
        sig = self.det.evaluate(
            EvaluationRequest(action="delete the production database backups")
        )
        assert sig is not None
        assert sig.severity >= Severity.HIGH
        assert sig.plane is Plane.ACTION

    def test_irreversible_plus_system_target_and_breadth_is_critical(self) -> None:
        sig = self.det.evaluate(
            EvaluationRequest(action="overwrite every file under /etc --recursive")
        )
        assert sig is not None
        assert sig.severity is Severity.CRITICAL

    def test_breadth_without_irreversible_verb_not_flagged(self) -> None:
        # "list everything in production" is wide but reads only
        assert (
            self.det.evaluate(EvaluationRequest(action="list everything in production"))
            is None
        )

    def test_safe_action_not_flagged(self) -> None:
        assert self.det.evaluate(EvaluationRequest(action="cat config.yaml")) is None

    def test_empty_action(self) -> None:
        assert self.det.evaluate(EvaluationRequest(action="")) is None

    def test_irreversible_verb_without_scope_not_flagged(self) -> None:
        # a plain "delete temp" — irreversible but no system / production scope.
        # The blast estimator no longer fires on a verb alone (that drove false
        # blocks on scoped local cleanups); path-aware command rules own those.
        assert self.det.evaluate(EvaluationRequest(action="delete temp")) is None

    def test_irreversible_plus_system_target_is_flagged(self) -> None:
        sig = self.det.evaluate(EvaluationRequest(action="wipe /etc recursively"))
        assert sig is not None and sig.severity >= Severity.HIGH

    def test_echoed_destructive_text_is_not_an_effector_action(self) -> None:
        assert self.det.evaluate(EvaluationRequest(action="X=rm; echo $X -rf /")) is None


class TestOriginTaint:
    det = OriginTaintDetector()

    def test_untrusted_mutating_action_is_high(self) -> None:
        sig = self.det.evaluate(
            EvaluationRequest(
                action="delete all user records",
                action_provenance="retrieved",
            )
        )
        assert sig is not None
        assert sig.severity is Severity.HIGH

    def test_untrusted_readonly_action_is_medium(self) -> None:
        sig = self.det.evaluate(
            EvaluationRequest(action="list the files", action_provenance="untrusted")
        )
        assert sig is not None
        assert sig.severity is Severity.MEDIUM

    def test_user_origin_not_flagged(self) -> None:
        assert (
            self.det.evaluate(
                EvaluationRequest(action="delete records", action_provenance="user")
            )
            is None
        )

    def test_unknown_origin_not_flagged(self) -> None:
        assert self.det.evaluate(EvaluationRequest(action="delete records")) is None

    def test_empty_action(self) -> None:
        assert (
            self.det.evaluate(EvaluationRequest(action="", action_provenance="untrusted"))
            is None
        )

    def test_provenance_case_insensitive(self) -> None:
        sig = self.det.evaluate(
            EvaluationRequest(action="rm x", action_provenance="TOOL_OUTPUT")
        )
        assert sig is not None


class TestIntentConsistency:
    det = IntentConsistencyDetector()

    def test_destructive_action_under_readonly_task_is_high(self) -> None:
        sig = self.det.evaluate(
            EvaluationRequest(
                query="summarise the quarterly report",
                action="DROP TABLE reports",
            )
        )
        assert sig is not None
        assert sig.severity is Severity.HIGH

    def test_mutating_action_under_readonly_task_is_medium(self) -> None:
        sig = self.det.evaluate(
            EvaluationRequest(query="show me the users", action="update users set x=1")
        )
        assert sig is not None
        assert sig.severity is Severity.MEDIUM

    def test_mutation_authorised_by_task_not_flagged(self) -> None:
        assert (
            self.det.evaluate(
                EvaluationRequest(
                    query="delete the stale records", action="delete from t"
                )
            )
            is None
        )

    def test_readonly_action_not_flagged(self) -> None:
        assert (
            self.det.evaluate(
                EvaluationRequest(query="summarise the report", action="cat report.txt")
            )
            is None
        )

    def test_unclear_task_intent_not_flagged(self) -> None:
        # task is neither clearly read-only nor mutating -> do not guess
        assert (
            self.det.evaluate(
                EvaluationRequest(query="the database", action="drop table t")
            )
            is None
        )

    def test_missing_query_or_action(self) -> None:
        assert self.det.evaluate(EvaluationRequest(action="rm -rf /")) is None
        assert self.det.evaluate(EvaluationRequest(query="read it")) is None
