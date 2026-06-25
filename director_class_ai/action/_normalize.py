# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
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

import ast
import base64
import binascii
import bz2
import gzip
import importlib
import lzma
import re
import shlex
import unicodedata
import zlib
from collections.abc import Callable

__all__ = ["expand", "rust_backend_available"]

_MAX_DEPTH = 4
_MAX_FORMS = 64

_WS = re.compile(r"\s+")
_QUOTE_BREAK = re.compile(r"(?<=\w)(?:''|\"\")(?=\w)")
_BACKSLASH_BREAK = re.compile(r"(?<=\w)\\(?=\w)")
_SPLIT_FLAGS = re.compile(r"(\s-[a-zA-Z]+)\s+-([a-zA-Z]+)")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_B64_CONTEXT = re.compile(r"\bbase64\b|\b(?:ba)?sh\b\s*$|\|\s*(?:ba)?sh\b", re.IGNORECASE)
_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")
_OCTAL_RUN = re.compile(r"(?:\\[0-7]{1,3}){2,}")
_IFS = re.compile(r"\$\{IFS\}|\$IFS\b")
_ZERO_WIDTH = re.compile("[\u200b-\u200f\ufeff]")
_ALIAS = re.compile(r"alias\s+\w+=['\"]([^'\"]+)['\"]", re.IGNORECASE)
_CMD_SUB = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
_ECHO_SUB = re.compile(r"\$\(\s*(?:echo|printf)\s+(?:-e\s+)?([^()]*?)\)", re.IGNORECASE)
_ECHO_PREFIX = re.compile(r"^\s*(?:echo|printf)\s+(?:-e\s+)?", re.IGNORECASE)
_ENV_ASSIGN = re.compile(
    r"(?:^|[;&]\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)="
    r"(?P<value>'[^']*'|\"[^\"]*\"|[^\s;&|]+)"
)
_BRACE_LIST = re.compile(r"\{([^{}\s]{1,96})\}")
_ARITH = re.compile(r"\$\(\((?P<expr>[^()]{1,64})\)\)")
_PRINTF_ARITH_OCTAL = re.compile(
    r"printf\s+['\"]\\\\%0?3?o['\"]\s+\$\(\((?P<expr>[^()]{1,64})\)\)",
    re.IGNORECASE,
)
_XARGS_TEMPLATE = re.compile(
    r"^\s*(?:printf|echo)\s+(?:-e\s+)?(?P<payload>.+?)"
    r"\s*\|\s*xargs\s+-I\s*(?P<placeholder>\S+)"
    r"\s+(?P<template>\S+)(?P<args>.*)$",
    re.IGNORECASE,
)
_SIMPLE_COMMAND_WORD = re.compile(r"[A-Za-z0-9_./-]+")
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "к": "k",
        "м": "m",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "α": "a",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "χ": "x",
    }
)

_RustExpand = Callable[[str, int, int], list[str]]


def _load_rust_expand() -> _RustExpand | None:
    """Return the optional Rust expander when the extension is installed."""
    try:
        rust_module = importlib.import_module("director_class_ai._rust")
    except ImportError:
        return None
    expand_rust = getattr(rust_module, "expand", None)
    return expand_rust if callable(expand_rust) else None


def rust_backend_available() -> bool:
    """Return whether the optional Rust normalisation extension can be imported."""
    return _load_rust_expand() is not None


def _printable_text(raw: bytes) -> str | None:
    """Decode printable bytes to one whitespace-normalised command string."""
    try:
        text = _WS.sub(" ", raw.decode("utf-8")).strip()
    except UnicodeDecodeError:
        return None
    return text if text and text.isprintable() else None


def _merge_split_flags(text: str) -> str:
    """Join ``-r -f`` into ``-rf`` until stable (attackers split flags to evade)."""
    prev = None
    while prev != text:
        prev = text
        text = _SPLIT_FLAGS.sub(r"\1\2", text)
    return text


def _safe_shell_arithmetic(expr: str) -> int | None:
    """Evaluate a bounded shell-arithmetic subset used in obfuscated bytes."""
    allowed_binops = (
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Mod,
        ast.LShift,
        ast.RShift,
        ast.BitOr,
        ast.BitAnd,
        ast.BitXor,
    )
    allowed_unary = (ast.UAdd, ast.USub, ast.Invert)

    def walk(node: ast.AST) -> int | None:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, allowed_unary):
            value = walk(node.operand)
            if value is None:
                return None
            if isinstance(node.op, ast.UAdd):
                return value
            if isinstance(node.op, ast.USub):
                return -value
            return ~value
        if isinstance(node, ast.BinOp) and isinstance(node.op, allowed_binops):
            left = walk(node.left)
            right = walk(node.right)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Mod) and right != 0:
                return left % right
            if isinstance(node.op, ast.LShift) and 0 <= right <= 16:
                return left << right
            if isinstance(node.op, ast.RShift) and 0 <= right <= 16:
                return left >> right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
        return None

    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None
    value = walk(tree)
    if value is None or not -(1 << 20) <= value <= (1 << 20):
        return None
    return value


def _arithmetic_expansions(command: str) -> list[str]:
    """Reveal bounded ``$((...))`` expansions as decimal shell output."""
    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        value = _safe_shell_arithmetic(match.group("expr"))
        if value is None:
            return match.group(0)
        changed = True
        return str(value)

    substituted = _ARITH.sub(repl, command)
    return [substituted] if changed and substituted != command else []


def _brace_expansions(command: str) -> list[str]:
    """Reveal small shell brace lists used to assemble command words or argv."""
    forms: list[str] = []
    for match in _BRACE_LIST.finditer(command):
        parts = match.group(1).split(",")
        if len(parts) < 2:
            continue
        if all(part == "" for part in parts):
            continue
        if len(parts) > 8 or not all(len(part) <= 32 for part in parts):
            continue

        start, end = match.span()
        prev = command[start - 1] if start > 0 else " "
        nxt = command[end] if end < len(command) else " "
        whole_word = prev.isspace() and (nxt.isspace() or nxt in "|;&")
        if whole_word:
            forms.append(f"{command[:start]}{' '.join(parts)}{command[end:]}")
        for part in parts:
            forms.append(f"{command[:start]}{part}{command[end:]}")
    return forms


def _decode_base64_payloads(command: str) -> list[str]:
    """Decode base64 tokens when the command pipes them into a shell."""
    if not _B64_CONTEXT.search(command):
        return []
    decoded: list[str] = []
    for token in _B64_TOKEN.findall(command):
        try:
            raw = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded.extend(_decode_binary_payloads(raw))
    return decoded


def _decode_binary_payloads(raw: bytes) -> list[str]:
    """Decode plain and common compressed payloads into printable text only."""
    out: list[str] = []
    direct = _printable_text(raw)
    if direct is not None:
        out.append(direct)
    for decoder in (gzip.decompress, zlib.decompress, bz2.decompress, lzma.decompress):
        try:
            text = _printable_text(decoder(raw))
        except (OSError, EOFError, zlib.error, lzma.LZMAError):
            continue
        if text is not None:
            out.append(text)
    return out


def _decode_hex_runs(command: str) -> list[str]:
    r"""Decode runs of ``\xHH`` escapes into their text."""
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
    r"""Substitute each ``\xHH`` run with its text in place, keeping the rest.

    Reveals ANSI-C forms like ``$'\x72\x6d' -rf /`` where the hidden verb is
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


def _decode_octal_run(run: str) -> str | None:
    """Decode one run of POSIX-style octal escapes, returning printable text only."""
    octets = re.findall(r"\\([0-7]{1,3})", run)
    try:
        text = bytes(int(octet, 8) for octet in octets).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    text = _WS.sub(" ", text).strip()
    return text if text and text.isprintable() else None


def _decode_octal_runs(command: str) -> list[str]:
    r"""Decode runs of ``\ooo`` escapes into their text."""
    decoded: list[str] = []
    for run in _OCTAL_RUN.findall(command):
        text = _decode_octal_run(run)
        if text is not None:
            decoded.append(text)
    return decoded


def _decode_octal_inplace(command: str) -> list[str]:
    """Substitute each octal escape run in place, preserving surrounding syntax."""

    def repl(match: re.Match[str]) -> str:
        return _decode_octal_run(match.group(0)) or match.group(0)

    substituted = _OCTAL_RUN.sub(repl, command)
    return [substituted] if substituted != command else []


def _first_shell_word(text: str) -> str:
    """Return the first shell word after quote handling, or an empty string."""
    try:
        words = shlex.split(text)
    except ValueError:
        return ""
    return words[0] if words else ""


def _xargs_reconstructions(command: str) -> list[str]:
    """Reveal ``printf verb | xargs -I{} {} args`` without expanding payloads."""
    match = _XARGS_TEMPLATE.match(command)
    if match is None:
        return []

    placeholder = match.group("placeholder")
    template = match.group("template")
    if template != placeholder:
        return []

    verb = _first_shell_word(match.group("payload"))
    if not verb or not _SIMPLE_COMMAND_WORD.fullmatch(verb):
        return []

    args = match.group("args").strip()
    return [f"{verb} {args}".strip()]


def _xargs_arithmetic_printf_reconstructions(command: str) -> list[str]:
    """Reveal arithmetic-built octal bytes piped into an ``xargs`` command word."""
    match = _XARGS_TEMPLATE.match(command)
    if match is None:
        return []

    placeholder = match.group("placeholder")
    template = match.group("template")
    if template != placeholder:
        return []

    octets: list[int] = []
    for expr_match in _PRINTF_ARITH_OCTAL.finditer(match.group("payload")):
        value = _safe_shell_arithmetic(expr_match.group("expr"))
        if value is None or not 0 <= value <= 255:
            return []
        octets.append(value)
    if not octets or len(octets) > 64:
        return []

    text = _printable_text(bytes(octets))
    if text is None or not _SIMPLE_COMMAND_WORD.fullmatch(text):
        return []

    args = match.group("args").strip()
    return [f"{text} {args}".strip()]


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


def _unicode_reveals(command: str) -> list[str]:
    """Reveal fullwidth, zero-width, and common Cyrillic/Greek homoglyph forms."""
    normalised = unicodedata.normalize("NFKC", command)
    stripped = _ZERO_WIDTH.sub("", normalised)
    translated = stripped.translate(_HOMOGLYPHS)
    return [form for form in (normalised, stripped, translated) if form != command]


def _strip_shell_quotes(value: str) -> str:
    """Strip one simple shell-quote layer from an assignment value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _env_var_reconstructions(command: str) -> list[str]:
    """Reveal ``X=rm; $X -rf /`` only when ``$X`` is the command word."""
    assignments = {
        match.group("name"): _strip_shell_quotes(match.group("value"))
        for match in _ENV_ASSIGN.finditer(command)
    }
    forms: list[str] = []
    for name, value in assignments.items():
        if not value or not value.isprintable() or len(value) > 256:
            continue
        command_var = re.compile(
            rf"(?:^|[;&]\s*)\$(?:{re.escape(name)}|\{{{re.escape(name)}\}})"
            rf"(?P<args>(?:\s+[^;&|]+)*)"
        )
        for match in command_var.finditer(command):
            args = match.group("args").strip()
            forms.append(f"{value} {args}".strip())
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
    out.extend(_unicode_reveals(norm))
    out.extend(_decode_base64_payloads(command))
    out.extend(_decode_hex_runs(command))
    out.extend(_decode_hex_inplace(command))
    out.extend(_decode_octal_runs(command))
    out.extend(_decode_octal_inplace(command))
    out.extend(_brace_expansions(command))
    out.extend(_arithmetic_expansions(command))
    out.extend(_xargs_reconstructions(command))
    out.extend(_xargs_arithmetic_printf_reconstructions(command))
    out.extend(_command_substitutions(command))
    out.extend(_env_var_reconstructions(command))
    out.extend(_ALIAS.findall(command))
    return out


def _expand_python(
    command: str, *, max_depth: int = _MAX_DEPTH, max_forms: int = _MAX_FORMS
) -> list[str]:
    """Return the Python reference expansion for one command.

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


def expand(
    command: str, *, max_depth: int = _MAX_DEPTH, max_forms: int = _MAX_FORMS
) -> list[str]:
    """Return *command* plus its de-obfuscated equivalents, peeled recursively.

    The optional Rust extension is used only when it produces the same ordered
    forms as the Python reference. That parity guard keeps detector behaviour
    stable while allowing the security-critical normalisation path to be
    rustified incrementally.
    """
    reference = _expand_python(command, max_depth=max_depth, max_forms=max_forms)
    rust_expand = _load_rust_expand()
    if rust_expand is None:
        return reference
    try:
        rust_forms = rust_expand(command, max_depth, max_forms)
    except (RuntimeError, ValueError):
        return reference
    return rust_forms if rust_forms == reference else reference
