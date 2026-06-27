# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — evidence technique tags

"""Technique tags for SOC-facing evidence records.

The tags are operational triage metadata. They map detector signal names to
bounded MITRE ATLAS and OWASP Agentic Security Initiative labels without claiming
certification, complete coverage, or prevention of the underlying technique.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

__all__ = [
    "TechniqueTag",
    "technique_ids_for_findings",
    "technique_tags_for_findings",
]

TechniqueFramework = Literal["MITRE ATLAS", "OWASP ASI"]

_CLAIM_BOUNDARY = (
    "Operational triage tag for audit/SOC correlation; does not assert "
    "certification, complete coverage, or prevention."
)


@dataclass(frozen=True)
class TechniqueTag:
    """Bounded adversary-technique metadata for one detector finding."""

    framework: TechniqueFramework
    technique_id: str
    technique_name: str
    finding: str
    claim_boundary: str = _CLAIM_BOUNDARY

    def to_json(self) -> dict[str, str]:
        """Return deterministic JSON-ready technique fields."""
        return {
            "framework": self.framework,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "finding": self.finding,
            "claim_boundary": self.claim_boundary,
        }


def technique_tags_for_findings(findings: Sequence[str]) -> tuple[TechniqueTag, ...]:
    """Return deduplicated technique tags for detector signal names."""
    tags: list[TechniqueTag] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        for tag in _tags_for_finding(finding):
            key = (tag.framework, tag.technique_id, tag.finding)
            if key not in seen:
                seen.add(key)
                tags.append(tag)
    return tuple(tags)


def technique_ids_for_findings(findings: Sequence[str]) -> tuple[str, ...]:
    """Return stable technique identifiers for detector signal names."""
    return tuple(
        dict.fromkeys(tag.technique_id for tag in technique_tags_for_findings(findings))
    )


def _tags_for_finding(finding: str) -> tuple[TechniqueTag, ...]:
    direct = _TECHNIQUE_MAP.get(finding)
    if direct is not None:
        return tuple(_tag(finding, *item) for item in direct)

    if finding.startswith("mcp_"):
        return (
            _tag(finding, "OWASP ASI", "ASI04", "Agentic Supply Chain Vulnerabilities"),
            _tag(finding, "MITRE ATLAS", "AML.T0110", "AI Agent Tool Poisoning"),
        )
    if finding.startswith("capability_"):
        return (
            _tag(finding, "OWASP ASI", "ASI03", "Identity and Privilege Abuse"),
            _tag(finding, "MITRE ATLAS", "AML.T0061", "AI Agent Tools"),
        )
    if finding.startswith("browser_"):
        return (
            _tag(finding, "OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
            _tag(finding, "MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
        )
    return ()


def _tag(
    finding: str,
    framework: TechniqueFramework,
    technique_id: str,
    technique_name: str,
) -> TechniqueTag:
    return TechniqueTag(
        framework=framework,
        technique_id=technique_id,
        technique_name=technique_name,
        finding=finding,
    )


_TECHNIQUE_MAP: Mapping[str, tuple[tuple[TechniqueFramework, str, str], ...]] = {
    "approval_required": (("OWASP ASI", "ASI09", "Human-Agent Trust Exploitation"),),
    "availability_loss": (("OWASP ASI", "ASI08", "Cascading Failures"),),
    "bucket_deletion": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
    ),
    "causal_takeover": (
        ("OWASP ASI", "ASI01", "Agent Goal Hijack"),
        ("MITRE ATLAS", "AML.T0051", "LLM Prompt Injection"),
    ),
    "datastore_drop": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
    ),
    "datastore_flush": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
    ),
    "delayed_malicious_objective": (
        ("OWASP ASI", "ASI06", "Memory and Context Poisoning"),
        ("MITRE ATLAS", "AML.T0058", "AI Agent Context Poisoning"),
    ),
    "destructive_command": (
        ("OWASP ASI", "ASI05", "Unexpected Code Execution"),
        ("MITRE ATLAS", "AML.T0050", "Command and Scripting Interpreter"),
    ),
    "disk_overwrite": (
        ("OWASP ASI", "ASI05", "Unexpected Code Execution"),
        ("MITRE ATLAS", "AML.T0050", "Command and Scripting Interpreter"),
    ),
    "exfiltration": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0086", "Exfiltration via AI Agent Tool Invocation"),
    ),
    "filesystem_format": (
        ("OWASP ASI", "ASI05", "Unexpected Code Execution"),
        ("MITRE ATLAS", "AML.T0050", "Command and Scripting Interpreter"),
    ),
    "fork_bomb": (
        ("OWASP ASI", "ASI08", "Cascading Failures"),
        ("MITRE ATLAS", "AML.T0050", "Command and Scripting Interpreter"),
    ),
    "history_rewrite": (("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),),
    "infra_teardown": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
    ),
    "memory_poisoning": (
        ("OWASP ASI", "ASI06", "Memory and Context Poisoning"),
        ("MITRE ATLAS", "AML.T0058", "AI Agent Context Poisoning"),
    ),
    "memory_secret_leakage": (
        ("OWASP ASI", "ASI03", "Identity and Privilege Abuse"),
        ("MITRE ATLAS", "AML.T0086", "Exfiltration via AI Agent Tool Invocation"),
    ),
    "mcp_remote_auth": (
        ("OWASP ASI", "ASI03", "Identity and Privilege Abuse"),
        ("OWASP ASI", "ASI04", "Agentic Supply Chain Vulnerabilities"),
        ("MITRE ATLAS", "AML.T0061", "AI Agent Tools"),
    ),
    "mcp_tool_call": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
    ),
    "origin_taint": (
        ("OWASP ASI", "ASI01", "Agent Goal Hijack"),
        ("MITRE ATLAS", "AML.T0051", "LLM Prompt Injection"),
    ),
    "persistent_instruction_injection": (
        ("OWASP ASI", "ASI06", "Memory and Context Poisoning"),
        ("MITRE ATLAS", "AML.T0058", "AI Agent Context Poisoning"),
    ),
    "privilege_escalation": (("OWASP ASI", "ASI03", "Identity and Privilege Abuse"),),
    "process_kill": (("OWASP ASI", "ASI08", "Cascading Failures"),),
    "remanentia_memory_mutation_approval": (
        ("OWASP ASI", "ASI06", "Memory and Context Poisoning"),
        ("MITRE ATLAS", "AML.T0058", "AI Agent Context Poisoning"),
    ),
    "sidecar_halt": (("OWASP ASI", "ASI10", "Rogue Agents"),),
    "sql_drop": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
    ),
    "sql_truncate": (
        ("OWASP ASI", "ASI02", "Tool Misuse and Exploitation"),
        ("MITRE ATLAS", "AML.T0053", "AI Agent Tool Invocation"),
    ),
    "stale_tool_schema": (
        ("OWASP ASI", "ASI04", "Agentic Supply Chain Vulnerabilities"),
        ("MITRE ATLAS", "AML.T0110", "AI Agent Tool Poisoning"),
    ),
    "task_plan_drift": (
        ("OWASP ASI", "ASI01", "Agent Goal Hijack"),
        ("MITRE ATLAS", "AML.T0051", "LLM Prompt Injection"),
    ),
}
