# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — shell segment helpers for action-plane detectors

"""Small shell-token helpers used by action-plane detectors."""

from __future__ import annotations

import shlex

__all__ = [
    "is_print_only_command",
    "shell_segments",
    "starts_with_print_command",
    "strip_print_segments",
]

_PRINT_COMMANDS = frozenset({"echo", "printf"})
_SEPARATORS = frozenset(";&|")


def shell_segments(command: str) -> tuple[str, ...]:
    """Split a shell command on unquoted command separators."""
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for char in command:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            current.append(char)
            quote = char
            continue
        if char in _SEPARATORS:
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            continue
        current.append(char)

    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return tuple(segments)


def starts_with_print_command(segment: str) -> bool:
    """Return whether a shell segment starts with optional env then echo/printf."""
    for token in _shell_words(segment):
        if _is_shell_assignment(token):
            continue
        return token in _PRINT_COMMANDS
    return False


def is_print_only_command(command: str) -> bool:
    """Return whether a full command is a single non-redirecting print segment."""
    segments = shell_segments(command)
    return (
        len(segments) == 1
        and starts_with_print_command(segments[0])
        and not _has_unquoted_redirection(segments[0])
    )


def strip_print_segments(command: str) -> str:
    """Remove shell segments that only print text rather than execute it."""
    return " ".join(
        segment
        for segment in shell_segments(command)
        if not (
            starts_with_print_command(segment)
            and not _has_unquoted_redirection(segment)
        )
    )


def _shell_words(segment: str) -> tuple[str, ...]:
    try:
        return tuple(shlex.split(segment, posix=True))
    except ValueError:
        return tuple(segment.split())


def _is_shell_assignment(token: str) -> bool:
    name, separator, _value = token.partition("=")
    return bool(separator and name and _is_shell_name(name))


def _is_shell_name(name: str) -> bool:
    first = name[0]
    if not (first == "_" or "A" <= first <= "Z" or "a" <= first <= "z"):
        return False
    return all(
        char == "_" or "0" <= char <= "9" or "A" <= char <= "Z" or "a" <= char <= "z"
        for char in name
    )


def _has_unquoted_redirection(segment: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in segment:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in {"<", ">"}:
            return True
    return False
