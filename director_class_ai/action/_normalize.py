# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-command de-obfuscation

"""Expand a command into the equivalent forms an attacker uses to evade matching.

The evasion test showed a single regex pass over the raw command misses real
bypasses — split flags (``rm -r -f /``), quote-breaks (``r''m -rf /``), base64
payloads piped to a shell, and alias indirection. Rather than duplicate the
detector (which, being deterministic, would just repeat the miss), we run it over
*de-obfuscated variants* of the input — the same module on transformed input is
the redundancy that actually produces a different, better result. ``expand``
returns every candidate form; a detector flags if any form matches.

All transforms are conservative and additive: they only ever *reveal* a hidden
command, never invent one, so a safe command expands to safe forms.
"""

from __future__ import annotations

import base64
import binascii
import re

__all__ = ["expand"]

_WS = re.compile(r"\s+")
_QUOTE_BREAK = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")
_BACKSLASH_BREAK = re.compile(r"(?<=\w)\\(?=\w)")
_SPLIT_FLAGS = re.compile(r"(\s-[a-zA-Z]+)\s+-([a-zA-Z]+)")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_B64_CONTEXT = re.compile(r"\bbase64\b|\b(?:ba)?sh\b\s*$|\|\s*(?:ba)?sh\b", re.IGNORECASE)
_ALIAS = re.compile(r"alias\s+\w+=['\"]([^'\"]+)['\"]", re.IGNORECASE)


def _merge_split_flags(text: str) -> str:
    """Join ``-r -f`` into ``-rf`` until stable (attackers split flags to evade)."""
    prev = None
    while prev != text:
        prev = text
        text = _SPLIT_FLAGS.sub(r"\1\2", text)
    return text


def _decode_base64_payloads(command: str) -> list[str]:
    """Decode base64 tokens when the command pipes them into a shell."""
    if not _B64_CONTEXT.search(command):
        return []
    decoded: list[str] = []
    for token in _B64_TOKEN.findall(command):
        try:
            raw = base64.b64decode(token, validate=True)
            text = _WS.sub(" ", raw.decode("utf-8")).strip()
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if text and text.isprintable():
            decoded.append(text)
    return decoded


def expand(command: str) -> list[str]:
    """Return the original command plus its de-obfuscated equivalents."""
    forms: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            forms.append(value)

    add(command)
    norm = _WS.sub(" ", command).strip()
    add(norm)
    dequoted = _BACKSLASH_BREAK.sub("", _QUOTE_BREAK.sub("", norm))
    dequoted = dequoted.replace("''", "").replace('""', "")
    add(dequoted)
    add(_merge_split_flags(dequoted))
    for payload in _decode_base64_payloads(command):
        add(payload)
        add(_merge_split_flags(payload))
    for body in _ALIAS.findall(command):
        add(body)
    return forms
