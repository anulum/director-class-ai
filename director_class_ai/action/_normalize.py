# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-command de-obfuscation

"""Expand a command into the equivalent forms an attacker uses to evade matching.

A single regex pass over the raw command misses real bypasses — split flags
(``rm -r -f /``), quote-breaks (``r''m -rf /``), base64 / hex payloads, command
substitution (``$(echo rm) -rf /``), and *nested* encodings. Rather than duplicate
the (deterministic) detector, we run it over de-obfuscated variants of the input:
the same module on transformed input is the redundancy that produces a different,
better result.

:func:`expand` applies the transforms *recursively* to a bounded depth, so a
base64 payload that itself contains a hex-encoded command is peeled layer by
layer. All transforms are additive — they only reveal a hidden command, never
invent one, so a safe command expands to safe forms — and the breadth is capped so
a hostile input cannot blow up the work.
"""

from __future__ import annotations

import base64
import binascii
import re

__all__ = ["expand"]

_MAX_DEPTH = 4
_MAX_FORMS = 64

_WS = re.compile(r"\s+")
_QUOTE_BREAK = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")
_BACKSLASH_BREAK = re.compile(r"(?<=\w)\\(?=\w)")
_SPLIT_FLAGS = re.compile(r"(\s-[a-zA-Z]+)\s+-([a-zA-Z]+)")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_B64_CONTEXT = re.compile(r"\bbase64\b|\b(?:ba)?sh\b\s*$|\|\s*(?:ba)?sh\b", re.IGNORECASE)
_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")
_IFS = re.compile(r"\$\{IFS\}|\$IFS\b")
_ALIAS = re.compile(r"alias\s+\w+=['\"]([^'\"]+)['\"]", re.IGNORECASE)
_CMD_SUB = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
_ECHO_SUB = re.compile(r"\$\(\s*(?:echo|printf)\s+(?:-e\s+)?([^()]*?)\)", re.IGNORECASE)
_ECHO_PREFIX = re.compile(r"^\s*(?:echo|printf)\s+(?:-e\s+)?", re.IGNORECASE)


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


def _decode_hex_runs(command: str) -> list[str]:
    """Decode runs of ``\\xHH`` escapes into their text."""
    decoded: list[str] = []
    for run in _HEX_RUN.findall(command):
        pairs = run.split("\\x")[1:]
        try:
            text = bytes(int(h, 16) for h in pairs).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        text = _WS.sub(" ", text).strip()
        if text and text.isprintable():
            decoded.append(text)
    return decoded


def _decode_hex_inplace(command: str) -> list[str]:
    """Substitute each ``\\xHH`` run with its text *in place*, keeping the rest.

    Reveals ANSI-C forms like ``$'\\x72\\x6d' -rf /`` where the hidden verb is
    embedded among literal arguments (extracting the run alone would lose them).
    """

    def repl(match: re.Match[str]) -> str:
        pairs = match.group(0).split("\\x")[1:]
        try:
            text = bytes(int(h, 16) for h in pairs).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return match.group(0)
        return text if text.isprintable() else match.group(0)

    substituted = _HEX_RUN.sub(repl, command)
    return [substituted] if substituted != command else []


def _command_substitutions(command: str) -> list[str]:
    """Reveal ``$(...)`` / backtick substitutions and inline ``$(echo ...)``."""
    forms: list[str] = []
    # inline echo/printf substitution: "$(echo rm) -rf /" -> "rm -rf /"
    inlined = _ECHO_SUB.sub(lambda m: m.group(1).strip("'\" "), command)
    if inlined != command:
        forms.append(inlined)
    for groups in _CMD_SUB.findall(command):
        inner = (groups[0] or groups[1]).strip()
        if not inner:
            continue
        forms.append(inner)
        stripped = _ECHO_PREFIX.sub("", inner).strip("'\" ")
        if stripped and stripped != inner:
            forms.append(stripped)
    return forms


def _transform_once(command: str) -> list[str]:
    """One layer of de-obfuscation: all direct transforms of *command*."""
    out: list[str] = []
    norm = _WS.sub(" ", command).strip()
    out.append(norm)
    dequoted = _BACKSLASH_BREAK.sub("", _QUOTE_BREAK.sub("", norm))
    dequoted = dequoted.replace("''", "").replace('""', "")
    out.append(dequoted)
    out.append(_merge_split_flags(dequoted))
    # Full quote-strip reveals embedded-quote breaks ('r"m"', "$'rm'") that the
    # empty-pair dequote misses; additive, so a safe command stays safe.
    out.append(norm.replace("$'", "").replace("'", "").replace('"', ""))
    # ${IFS} is a space substitute attackers use to avoid literal whitespace.
    out.append(_WS.sub(" ", _IFS.sub(" ", norm)).strip())
    out.extend(_decode_base64_payloads(command))
    out.extend(_decode_hex_runs(command))
    out.extend(_decode_hex_inplace(command))
    out.extend(_command_substitutions(command))
    out.extend(_ALIAS.findall(command))
    return out


def expand(
    command: str, *, max_depth: int = _MAX_DEPTH, max_forms: int = _MAX_FORMS
) -> list[str]:
    """Return *command* plus its de-obfuscated equivalents, peeled recursively.

    ``max_depth`` bounds the nesting peeled (base64-in-hex-in-…) and ``max_forms``
    caps the breadth so a hostile input cannot blow up the work.
    """
    forms: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> bool:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            forms.append(value)
            return True
        return False

    add(command)
    frontier = [command]
    for _ in range(max_depth):
        nxt: list[str] = []
        for cmd in frontier:
            for form in _transform_once(cmd):
                if len(forms) >= max_forms:
                    return forms
                if add(form):
                    nxt.append(form)
        if not nxt:
            break
        frontier = nxt
    return forms
