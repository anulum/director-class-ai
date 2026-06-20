# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — shared action-plane lexicon

"""Verb and target lexicons shared by the heuristic action detectors.

Kept in one place so blast-radius, origin-taint, and intent-consistency agree on
what counts as destructive / mutating / read-only, and so the sets are auditable
in a single file rather than drifting across detectors.
"""

from __future__ import annotations

import re

# Irreversible / catastrophic verbs — losing the data is the point.
IRREVERSIBLE = re.compile(
    r"\b(?:rm|delete|del|drop|destroy|truncate|wipe|purge|format|mkfs|"
    r"overwrite|erase|prune|shred|unlink)\b",
    re.IGNORECASE,
)

# State-changing verbs more broadly (includes irreversible + writes / sends).
MUTATING = re.compile(
    r"\b(?:rm|delete|del|drop|destroy|truncate|wipe|purge|format|overwrite|erase|"
    r"prune|shred|unlink|update|insert|write|create|deploy|push|send|post|put|"
    r"patch|exec|install|move|mv|chmod|chown|kill|shutdown|reboot|grant|revoke|"
    r"transfer|publish|merge|reset|rebase)\b",
    re.IGNORECASE,
)

# Task phrasing that asks only to read / understand, never to change anything.
READ_ONLY_TASK = re.compile(
    r"\b(?:summari[sz]e|list|read|show|display|explain|describe|analy[sz]e|"
    r"find|search|count|report|review|inspect|fetch|get|view|print|tell|"
    r"what|which|when|where|who|how\s+many|why)\b",
    re.IGNORECASE,
)

# Task phrasing that explicitly authorises a change.
MUTATING_TASK = re.compile(
    r"\b(?:delete|remove|drop|update|change|modify|create|add|deploy|install|"
    r"fix|write|edit|rename|move|migrate|reset|clean\s*up|purge|truncate|"
    r"restart|stop|start|kill|grant|revoke|push|merge|run|execute)\b",
    re.IGNORECASE,
)

# Production / sensitive scope indicators.
PRODUCTION = re.compile(
    r"\b(?:prod|production|live|master|main)\b|prod[-_.]", re.IGNORECASE
)

# System / high-value filesystem targets.
SYSTEM_TARGET = re.compile(
    r"(?:\s|^)(?:/(?:etc|var|usr|boot|dev|bin|lib|root|home|sys|proc)\b|/\s*$|/\*|~)"
    r"|[A-Za-z]:\\Windows",
    re.IGNORECASE,
)

# Breadth: recursion, wildcards, force, "all".
BREADTH = re.compile(
    r"(?:\s-[a-z]*r[a-z]*\b|--recursive\b|\*|--all\b|\s-[a-z]*f[a-z]*\b|"
    r"--force\b|\beverything\b|\bentire\b)",
    re.IGNORECASE,
)

UNTRUSTED_ORIGINS = frozenset(
    {"untrusted", "retrieved", "tool_output", "external", "document", "web"}
)
