# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — reversibility evidence detector

"""Detect irreversible action proposals that lack rollback evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping

from ..core import DetectorSignal, EvaluationRequest, Locus, Plane, Severity

__all__ = ["REVERSIBILITY_KEY", "ReversibilityDetector"]

REVERSIBILITY_KEY = "reversibility"

_ROOT_DELETE = re.compile(r"\brm\b[^|;&\n]*\s(?:/|/\*|~)(?:\s|$)", re.IGNORECASE)
_RECURSIVE_RM = re.compile(r"\brm\b(?=[^|;&\n]*-[a-z-]*r)(?=[^|;&\n]*-[a-z-]*f)", re.I)
_SQL_MUTATION = re.compile(
    r"\b(?:DROP\s+(?:TABLE|DATABASE|KEYSPACE|OWNED)|TRUNCATE\s+TABLE|"
    r"DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b",
    re.IGNORECASE,
)
_INFRA_DESTROY = re.compile(
    r"\b(?:terraform|pulumi)\s+destroy\b|\bkubectl\s+delete\s+namespace\b|"
    r"\baws\s+s3\s+rm\b.*\s--recursive\b",
    re.IGNORECASE,
)
_RAW_ARTIFACT_KEYS = frozenset(
    {
        "diff",
        "raw_diff",
        "dry_run_output",
        "command_output",
        "stdout",
        "stderr",
        "output",
    }
)
_REQUIRED_FIELDS = frozenset({"snapshot_id", "rollback_command", "transaction_id"})


class ReversibilityDetector:
    """Require rollback evidence before irreversible effector mutations proceed."""

    name = "reversibility"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Require digest-only rollback evidence for irreversible mutations."""
        action = request.action.strip()
        if not action:
            return None

        evidence = _evidence(request.metadata)
        raw_keys = sorted(_RAW_ARTIFACT_KEYS.intersection(evidence))
        if raw_keys:
            return _signal(
                Severity.HIGH,
                "raw_reversibility_artifact",
                f"raw reversibility artefact metadata forbidden: {', '.join(raw_keys)}",
            )

        severity = _irreversible_severity(action)
        if severity is None:
            return None

        missing = sorted(k for k in _REQUIRED_FIELDS if not evidence.get(k))
        has_artifact_digest = bool(
            evidence.get("dry_run_digest") or evidence.get("diff_digest")
        )
        if missing:
            return _signal(
                severity,
                "missing_reversibility",
                f"irreversible mutation lacks rollback evidence: {', '.join(missing)}",
            )
        if not has_artifact_digest:
            return _signal(
                Severity.HIGH,
                "missing_reversibility",
                "irreversible mutation lacks dry-run/diff artefact digest",
            )
        return None


def _evidence(metadata: Mapping[str, object]) -> Mapping[str, object]:
    value = metadata.get(REVERSIBILITY_KEY)
    return value if isinstance(value, Mapping) else {}


def _irreversible_severity(action: str) -> Severity | None:
    if _ROOT_DELETE.search(action):
        return Severity.CRITICAL
    if _SQL_MUTATION.search(action) or _INFRA_DESTROY.search(action):
        if re.search(
            r"\bDROP\s+DATABASE\b|\bkubectl\s+delete\s+namespace\b", action, re.I
        ):
            return Severity.CRITICAL
        return Severity.HIGH
    if _RECURSIVE_RM.search(action):
        return Severity.HIGH
    return None


def _signal(severity: Severity, signal_type: str, rationale: str) -> DetectorSignal:
    score = 0.97 if severity is Severity.CRITICAL else 0.9
    return DetectorSignal(
        detector="reversibility",
        plane=Plane.ACTION,
        score=score,
        locus=Locus.ACTION,
        signal_type=signal_type,
        severity=severity,
        rationale=rationale,
    )
