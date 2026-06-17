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
# Note: recursive ``rm`` is handled by the path-aware classifier below, not a rule,
# so a scoped local cleanup (``rm -rf node_modules``) is not blocked while a system
# / root / wildcard delete still is.
_RULES: tuple[_Rule, ...] = (
    # ── shell: irreversible mass destruction ───────────────────────────────────
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
        _rx(
            r"\bwipefs\b[^\n;&|]*(?:-a\b|--all\b)[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)"
        ),
        "filesystem_format",
        Severity.CRITICAL,
        "filesystem signature wipe on a block device",
    ),
    _Rule(
        _rx(r"\bsgdisk\b[^\n;&|]*--zap-all\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)"),
        "filesystem_format",
        Severity.CRITICAL,
        "partition table wipe on a block device",
    ),
    _Rule(
        _rx(r"\bblkdiscard\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)"),
        "disk_overwrite",
        Severity.CRITICAL,
        "discard of an entire block device",
    ),
    _Rule(
        _rx(
            r"\bcryptsetup\b[^\n;&|]*\bluksFormat\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)"
        ),
        "filesystem_format",
        Severity.CRITICAL,
        "LUKS format of a block device",
    ),
    _Rule(
        _rx(r"\bparted\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)[^\n;&|]*\bmklabel\b"),
        "filesystem_format",
        Severity.CRITICAL,
        "partition label rewrite on a block device",
    ),
    _Rule(
        _rx(r"\bfind\b.*\s-delete\b|\bfind\b.*-exec\s+rm\b"),
        "destructive_command",
        Severity.HIGH,
        "find -delete / -exec rm mass deletion",
    ),
    _Rule(
        _rx(r"\bfind\b[^\n;&|]*(?:/\s|/\s*$)[^\n;&|]*-exec\s+shred\b"),
        "destructive_command",
        Severity.HIGH,
        "find -exec shred over a root tree",
    ),
    _Rule(
        _rx(
            r"\bshred\b[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|~|"
            r"\bprod(?:uction)?\b)"
        ),
        "destructive_command",
        Severity.HIGH,
        "shred of a sensitive / production target",
    ),
    _Rule(
        _rx(
            r"\btar\b[^\n;&|]*--remove-files\b[^\n;&|]*"
            r"(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|~|\bprod(?:uction)?\b)"
        ),
        "destructive_command",
        Severity.HIGH,
        "tar --remove-files against a sensitive / production target",
    ),
    _Rule(
        _rx(r">\s*/dev/(?:sd|nvme|hd|vd|mmcblk)"),
        "disk_overwrite",
        Severity.CRITICAL,
        "redirect over a raw block device",
    ),
    _Rule(
        _rx(
            r"\brsync\b[^\n;&|]*--delete\b[^\n;&|]*"
            r"(?:/dev/null/?|(?:^|\s)(?:\.?/)?empty/)[^\n;&|]*"
            r"\s/(?:etc|var|srv|home|root|opt|usr|boot)\b"
        ),
        "destructive_command",
        Severity.HIGH,
        "rsync --delete mirror wipe of a sensitive target",
    ),
    _Rule(
        _rx(
            r"\btruncate\b[^\n;&|]*(?:-s\s*0|--size(?:=|\s)0)[^\n;&|]*"
            r"(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|\bprod(?:uction)?\b)"
        ),
        "destructive_command",
        Severity.HIGH,
        "truncate-to-zero of a sensitive / production target",
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
        _rx(
            r"\bchmod\s+-R\s+0{3,4}\b[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|\bprod(?:uction)?\b)"
        ),
        "permission_wipe",
        Severity.HIGH,
        "recursive permission denial on a sensitive / production target",
    ),
    _Rule(
        _rx(
            r"\bchown\s+-R\s+\S+\s+[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|\bprod(?:uction)?\b)"
        ),
        "permission_wipe",
        Severity.HIGH,
        "recursive ownership rewrite of a sensitive / production target",
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
        _rx(r"\b(?:terraform|pulumi)\s+destroy\b"),
        "infra_teardown",
        Severity.CRITICAL,
        "terraform / pulumi destroy tears down managed infrastructure",
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
    # ── availability: stopping/disabling services or the firewall ──────────────
    _Rule(
        _rx(r"\bsystemctl\s+(?:stop|disable|mask|kill)\b"),
        "availability_loss",
        Severity.HIGH,
        "stopping / disabling a system service",
    ),
    _Rule(
        _rx(r"\biptables\s+(?:-F|--flush)\b|\bufw\s+disable\b"),
        "availability_loss",
        Severity.HIGH,
        "flushing / disabling the host firewall",
    ),
    _Rule(
        _rx(r"\bdocker\s+stop\s+\$\(.*docker\s+ps"),
        "availability_loss",
        Severity.HIGH,
        "stopping every running container",
    ),
    # ── privilege escalation / persistence ─────────────────────────────────────
    _Rule(
        _rx(r">>?\s*/etc/sudoers|>\s*/etc/cron"),
        "privilege_escalation",
        Severity.HIGH,
        "writing a sudoers / cron backdoor",
    ),
    _Rule(
        _rx(r"\busermod\s+-a?G\s+[\w,]*sudo\b|\bchmod\s+[ug]\+s\b|\bpasswd\s+-d\b"),
        "privilege_escalation",
        Severity.HIGH,
        "granting privilege (sudo group / setuid / password removal)",
    ),
    # ── credential / data exfiltration to a network sink ───────────────────────
    _Rule(
        _rx(
            r"(?:cat|tail|head|less)\b[^|]*"
            r"(?:id_rsa|/etc/shadow|\.ssh/|\.aws/cred|secret|\.pem|\.key)\b"
            r"[^|]*\|\s*(?:curl|wget|nc|ncat|netcat)\b"
        ),
        "exfiltration",
        Severity.HIGH,
        "piping a secret file to a network tool",
    ),
    _Rule(
        _rx(
            r"\benv\b\s*\|\s*(?:curl|wget|nc|ncat)\b"
            r"|\baws\s+configure\s+get\b[^|]*\|\s*(?:curl|wget|nc)\b"
        ),
        "exfiltration",
        Severity.HIGH,
        "piping environment / credentials to a network tool",
    ),
    # ── datastore wipes the SQL rules do not cover ─────────────────────────────
    _Rule(
        _rx(r"\bdropDatabase\s*\(|\bDROP\s+KEYSPACE\b|\bDROP\s+OWNED\b"),
        "datastore_drop",
        Severity.CRITICAL,
        "dropping a NoSQL / Cassandra / owned-objects store",
    ),
    _Rule(
        _rx(r"\bFLUSH(?:ALL|DB)\b|\betcdctl\s+del\b.*--prefix"),
        "datastore_flush",
        Severity.HIGH,
        "flushing a key-value store",
    ),
    # ── Windows destructive idioms ─────────────────────────────────────────────
    _Rule(
        _rx(r"\brd\s+/s\b|\brmdir\s+/s\b"),
        "destructive_command",
        Severity.HIGH,
        "recursive Windows directory removal",
    ),
    _Rule(
        _rx(r"\bformat\s+[a-z]:"),
        "filesystem_format",
        Severity.CRITICAL,
        "format of a Windows drive",
    ),
    _Rule(
        _rx(r"\bcipher\s+/w\b"),
        "disk_overwrite",
        Severity.HIGH,
        "cipher /w wipes free disk space",
    ),
    # ── package-manager mass removal ───────────────────────────────────────────
    _Rule(
        _rx(
            r"\bpip\s+uninstall\b[^\n]*\s-r\b|\bnpm\s+uninstall\s+(?:-g|--global)\b"
            r"|\bapt(?:-get)?\s+(?:remove|purge|autoremove)\b[^\n]*--purge\b"
        ),
        "dependency_removal",
        Severity.HIGH,
        "bulk / global / purging package removal",
    ),
)

# Score is pattern-match confidence; severity carries "how bad if real".
_SEVERITY_SCORE = {
    Severity.CRITICAL: 0.97,
    Severity.HIGH: 0.9,
    Severity.MEDIUM: 0.6,
    Severity.LOW: 0.4,
}

# ── path-aware classification of a recursive ``rm`` ────────────────────────────
# A recursive rm is judged by *what it deletes*, not merely that it is recursive:
# a project-local or scratch path is an ordinary cleanup, a system / root / home /
# wildcard path is catastrophic. This is the precision fix for the kill-switch —
# blocking ``rm -rf node_modules`` makes the guard unusable, missing ``rm -rf /``
# makes it useless.
_RM_SEGMENT = re.compile(r"\brm\b([^|;&\n]*)", re.IGNORECASE)
_SHELL_SPLIT = re.compile(r"[|;&]")
_PRINT_COMMAND = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|[^\s;&|]+)\s+)*"
    r"(?:echo|printf)\b",
    re.IGNORECASE,
)
_SCRATCH_ABS = re.compile(r"^/(?:tmp|var/tmp)(?:/|$)")
_CRITICAL_TARGETS = frozenset(
    {"/", "/*", "~", "~/", "$HOME", ".", "./", "..", "*", "./*"}
)


def _is_recursive_flag(token: str) -> bool:
    """True for ``-r`` / ``-rf`` clusters and ``--recursive`` (not ``--force``)."""
    if token == "--recursive":
        return True
    if token.startswith("--"):
        return False
    return token.startswith("-") and ("r" in token or "R" in token)


def _target_severity(target: str) -> Severity | None:
    """Classify a single recursive-rm target by blast radius."""
    target = target.strip().strip("'\"")
    if not target or target.startswith("-"):
        return None
    if target in _CRITICAL_TARGETS or target.startswith(("~", "$HOME")):
        return Severity.CRITICAL
    if target.startswith("/"):
        if "*" in target:  # wildcard on an absolute path
            return Severity.CRITICAL
        if _SCRATCH_ABS.match(target):  # /tmp, /var/tmp scratch space
            return None
        return Severity.HIGH  # any other absolute path (system or otherwise)
    if target.startswith(".."):  # parent-directory traversal
        return Severity.HIGH
    return None  # relative / project-local path — an ordinary cleanup


def _rm_severity(form: str) -> Severity | None:
    """Severity of a recursive ``rm`` in *form*, or None if absent / local / safe."""
    worst: Severity | None = None
    for shell_segment in _SHELL_SPLIT.split(form):
        shell_segment = shell_segment.strip()
        if _PRINT_COMMAND.match(shell_segment):
            continue
        for segment in _RM_SEGMENT.findall(shell_segment):
            tokens = segment.split()
            if not any(_is_recursive_flag(t) for t in tokens):
                continue  # not recursive — a single-file rm is not a mass wipe
            for token in tokens:
                severity = _target_severity(token)
                if severity is not None and (worst is None or severity > worst):
                    worst = severity
    return worst


class DestructiveCommandDetector:
    """Tier-0 action-plane detector for catastrophic effector commands."""

    name = "destructive_command"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Match destructive command patterns across de-obfuscated action forms."""
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

        # Path-aware recursive-rm classification runs alongside the rule table.
        rm_severity = max(
            (s for f in forms if (s := _rm_severity(f)) is not None),
            default=None,
        )

        severity, signal_type, rationale = self._strongest(best, rm_severity)
        if severity is None:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=_SEVERITY_SCORE[severity],
            locus=Locus.ACTION,
            signal_type=signal_type,
            severity=severity,
            rationale=rationale,
        )

    @staticmethod
    def _strongest(
        rule: _Rule | None, rm_severity: Severity | None
    ) -> tuple[Severity | None, str, str]:
        """Pick the higher-severity of a matched rule and the rm classifier."""
        if rule is not None and (rm_severity is None or rule.severity >= rm_severity):
            return rule.severity, rule.signal_type, rule.rationale
        if rm_severity is not None:
            return (
                rm_severity,
                "destructive_command",
                "recursive force-delete of a root / home / system / wildcard path",
            )
        return None, "", ""
