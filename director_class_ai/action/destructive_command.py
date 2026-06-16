# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — destructive-command detector (action plane, tier 0)

"""Catch catastrophic effector commands before they run — the kill-switch core.

This is the cheap, tier-0 gate on the action plane: a pattern matcher over the
concrete command an autonomous agent is about to execute (shell, SQL, infra CLI).
It exists because an LLM that has been prompt-injected, has hallucinated a task,
or has simply reasoned poorly can emit ``rm -rf /`` or ``DROP DATABASE`` with the
same fluent confidence as a safe command — and behind the agent is an automated
effector that will run it. Rule matching is microseconds, so 99% of traffic clears
here and only a flagged command pays for the expensive ensemble + human review.

Matching is intentionally conservative toward *blocking* (the action plane is
fail-closed): variant flag spellings (``rm -rf`` / ``rm -fr`` / ``rm --force
--recursive``), whitespace, and the common destructive idioms are normalised so an
obfuscated catastrophe is not waved through. A match is "look here and block",
not a claim that nothing else is dangerous — absence of a match is *not* a safety
guarantee, which is why this is one tier of a defence-in-depth ensemble.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)
from ._normalize import expand

__all__ = ["DestructiveCommandDetector"]


@dataclass(frozen=True)
class _Rule:
    pattern: re.Pattern[str]
    signal_type: str
    severity: Severity
    rationale: str


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Ordered by descending severity within a family; the highest-severity match wins.
_RULES: tuple[_Rule, ...] = (
    # ── shell: irreversible mass destruction ───────────────────────────────────
    _Rule(
        _rx(
            r"\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force|"
            r"--force\s+--recursive)\b.*(?:\s/(?:\s|\*|$)|\s~|\s\*|\s\.\s*$)"
        ),
        "destructive_command",
        Severity.CRITICAL,
        "recursive force-delete of a root / home / wildcard path",
    ),
    _Rule(
        _rx(
            r"\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force|"
            r"--force\s+--recursive)\b"
        ),
        "destructive_command",
        Severity.HIGH,
        "recursive force-delete",
    ),
    _Rule(
        _rx(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        "fork_bomb",
        Severity.CRITICAL,
        "shell fork bomb",
    ),
    _Rule(
        _rx(r"\bdd\b.*\bof=/dev/(?:sd|nvme|hd|vd|mmcblk|disk)"),
        "disk_overwrite",
        Severity.CRITICAL,
        "raw write to a block device (dd of=/dev/…)",
    ),
    _Rule(
        _rx(r"\bmkfs(?:\.\w+)?\b"),
        "filesystem_format",
        Severity.CRITICAL,
        "filesystem format (mkfs)",
    ),
    _Rule(
        _rx(r"\bfind\b.*\s-delete\b|\bfind\b.*-exec\s+rm\b"),
        "destructive_command",
        Severity.HIGH,
        "find -delete / -exec rm mass deletion",
    ),
    _Rule(
        _rx(r">\s*/dev/(?:sd|nvme|hd|vd|mmcblk)"),
        "disk_overwrite",
        Severity.CRITICAL,
        "redirect over a raw block device",
    ),
    # ── shell: availability / privilege / remote exec ──────────────────────────
    _Rule(
        _rx(r"\b(?:shutdown|reboot|halt|poweroff)\b|\binit\s+0\b"),
        "availability_loss",
        Severity.HIGH,
        "host shutdown / reboot",
    ),
    _Rule(
        _rx(r"\bchmod\s+-R\s+0?777\b"),
        "permission_wipe",
        Severity.HIGH,
        "recursive world-writable permissions",
    ),
    _Rule(
        _rx(r"\b(?:kill(?:all)?\s+-9|kill\s+-9\s+-1)\b|\bkillall\b"),
        "process_kill",
        Severity.HIGH,
        "mass process termination",
    ),
    _Rule(
        _rx(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"),
        "remote_code_execution",
        Severity.HIGH,
        "pipe of remote content into a shell",
    ),
    _Rule(
        _rx(r"\bgit\s+push\b.*(?:--force\b|\s-f\b)"),
        "history_rewrite",
        Severity.HIGH,
        "force-push rewrites remote history",
    ),
    # ── SQL ────────────────────────────────────────────────────────────────────
    _Rule(
        _rx(r"\bdrop\s+(?:database|schema|table)\b"),
        "sql_drop",
        Severity.CRITICAL,
        "DROP of a database / schema / table",
    ),
    _Rule(
        _rx(r"\btruncate\s+table\b|\btruncate\b\s+\w+"),
        "sql_truncate",
        Severity.CRITICAL,
        "TRUNCATE empties a table irreversibly",
    ),
    _Rule(
        _rx(r"\bdelete\s+from\s+\w+\s*(?:;|$)"),
        "sql_unscoped_delete",
        Severity.HIGH,
        "DELETE without a WHERE clause",
    ),
    _Rule(
        _rx(r"\bupdate\s+\w+\s+set\b(?!.*\bwhere\b)"),
        "sql_unscoped_update",
        Severity.HIGH,
        "UPDATE without a WHERE clause",
    ),
    # ── infrastructure / cloud ─────────────────────────────────────────────────
    _Rule(
        _rx(r"\bterraform\s+destroy\b"),
        "infra_teardown",
        Severity.CRITICAL,
        "terraform destroy tears down managed infrastructure",
    ),
    _Rule(
        _rx(r"\bkubectl\s+delete\b.*(?:--all\b|\bnamespace\b)"),
        "infra_teardown",
        Severity.HIGH,
        "kubectl delete of a namespace / all resources",
    ),
    _Rule(
        _rx(r"\baws\s+s3\s+(?:rb|rm)\b.*(?:--force|--recursive)"),
        "bucket_deletion",
        Severity.HIGH,
        "recursive / forced S3 bucket deletion",
    ),
)

# Score is pattern-match confidence; severity carries "how bad if real".
_SEVERITY_SCORE = {
    Severity.CRITICAL: 0.97,
    Severity.HIGH: 0.9,
    Severity.MEDIUM: 0.6,
    Severity.LOW: 0.4,
}


class DestructiveCommandDetector:
    """Tier-0 action-plane detector for catastrophic effector commands."""

    name = "destructive_command"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        command = (request.action or "").strip()
        if not command:
            return None
        # Match every rule against all de-obfuscated forms — an obfuscated
        # catastrophe (split flags, quote-breaks, base64, alias) only has to
        # match in one revealed form to be caught.
        forms = expand(command)
        best: _Rule | None = None
        for rule in _RULES:
            if any(rule.pattern.search(f) for f in forms) and (
                best is None or rule.severity > best.severity
            ):
                best = rule
        if best is None:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=_SEVERITY_SCORE[best.severity],
            locus=Locus.ACTION,
            signal_type=best.signal_type,
            severity=best.severity,
            rationale=best.rationale,
        )
