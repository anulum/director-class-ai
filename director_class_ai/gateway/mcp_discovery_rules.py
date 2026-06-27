# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP discovery rule helpers

"""Rule helpers for reviewing MCP tools/list discovery descriptors."""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Protocol

__all__ = ["descriptor_poisoning_findings", "normalise_tool_name"]

_DISCOVERY_POISONING = re.compile(
    r"\b("
    r"ignore\s+(?:all\s+)?previous\s+instructions|"
    r"system\s+prompt|"
    r"developer\s+message|"
    r"always\s+(?:choose|use|call)|"
    r"prefer\s+this\s+tool|"
    r"exfiltrat(?:e|ion)|"
    r"send\s+(?:secrets?|credentials?)|"
    r"hidden\s+instruction"
    r")\b",
    re.IGNORECASE,
)
_PARAMETER_POISONING = re.compile(
    r"(?:^|[_\-.])("
    r"ignore(?:[_\-.]?previous)?(?:[_\-.]?instructions?)?|"
    r"system(?:[_\-.]?prompt|[_\-.]?message)?|"
    r"developer(?:[_\-.]?message)?|"
    r"hidden(?:[_\-.]?instruction)?|"
    r"override(?:[_\-.]?policy)?|"
    r"jailbreak|"
    r"always(?:[_\-.]?(?:use|call|choose))"
    r")(?:$|[_\-.])",
    re.IGNORECASE,
)
_PREFERENCE_MANIPULATION = re.compile(
    r"\b("
    r"always\s+(?:choose|use|call)|"
    r"prefer\s+this\s+tool|"
    r"highest\s+priority|"
    r"more\s+trusted\s+than|"
    r"bypass\s+(?:policy|approval|review)"
    r")\b",
    re.IGNORECASE,
)
_FALSE_ERROR_ESCALATION = re.compile(
    r"\b("
    r"(?:if|when)\s+(?:an?\s+)?(?:error|failure|exception)\b.{0,80}"
    r"(?:run|execute|call|invoke|use)\s+"
    r"(?:shell|terminal|bash|cmd|powershell|rm|curl|wget|delete|drop)|"
    r"on\s+(?:error|failure)\b.{0,80}(?:ask|tell)\s+the\s+user\s+to\s+run"
    r")\b",
    re.IGNORECASE,
)
_TOOL_TRANSFER = re.compile(
    r"\b("
    r"(?:call|invoke|delegate\s+to|transfer\s+to|chain\s+to)\s+"
    r"(?:another\s+)?(?:tool|server|agent)|"
    r"after\s+this\s+tool\b.{0,80}(?:call|invoke|use)\b"
    r")\b",
    re.IGNORECASE,
)
_MUTATING_PARAMETER = re.compile(
    r"(?:^|[_\-.])("
    r"command|cmd|shell|script|exec|execute|delete|remove|write|update|patch|"
    r"drop|truncate|query|sql|payload|body|url|webhook|callback|destination"
    r")(?:$|[_\-.])",
    re.IGNORECASE,
)
_READ_TOOL = re.compile(
    r"(?:^|[_\-.])(?:read|get|list|search|fetch|view|show|describe|query|find|"
    r"lookup|inspect|open|stat)(?:$|[_\-.])",
    re.IGNORECASE,
)
_READ_ALLOWED_PARAMETERS = frozenset(
    {
        "path",
        "file",
        "filename",
        "pattern",
        "glob",
        "query",
        "limit",
        "offset",
        "cursor",
        "encoding",
        "format",
        "include",
        "exclude",
        "recursive",
    }
)
_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])"
)
_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_MAX_DECODED_TEXT = 4096


class _DiscoveryDescriptor(Protocol):
    @property
    def server(self) -> str: ...

    @property
    def tool(self) -> str: ...

    @property
    def description(self) -> str: ...

    @property
    def instructions(self) -> str: ...

    @property
    def input_schema(self) -> Mapping[str, object]: ...

    @property
    def output_schema(self) -> Mapping[str, object]: ...

    @property
    def argument_schema(self) -> Mapping[str, object]: ...

    @property
    def hidden_metadata(self) -> Mapping[str, object]: ...

    @property
    def remote_auth(self) -> Mapping[str, object]: ...


def normalise_tool_name(value: str) -> str:
    """Return the collision key used for one discovery tool name."""
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def descriptor_poisoning_findings(
    descriptor: _DiscoveryDescriptor,
) -> tuple[str, ...]:
    """Return fail-closed discovery findings for a descriptor."""
    findings: list[str] = []
    text = _discovery_text(descriptor)
    hidden_text = _canonical(descriptor.hidden_metadata)
    parameter_names = _parameter_names(descriptor)
    default_texts = _default_texts(descriptor)

    if _matches(_DISCOVERY_POISONING, text):
        findings.append("discovery_poisoning")
    if any(_matches(_PARAMETER_POISONING, name) for name in parameter_names):
        findings.append("parameter_name_poisoning")
    if any(_matches(_DISCOVERY_POISONING, default) for default in default_texts):
        findings.append("schema_default_poisoning")
    if descriptor.hidden_metadata and (
        _matches(_DISCOVERY_POISONING, hidden_text)
        or _matches(_PREFERENCE_MANIPULATION, hidden_text)
    ):
        findings.append("hidden_metadata_poisoning")
    if _matches(_PREFERENCE_MANIPULATION, text):
        findings.append("preference_manipulation")
    if _matches(_FALSE_ERROR_ESCALATION, text):
        findings.append("false_error_escalation")
    if _matches(_TOOL_TRANSFER, text):
        findings.append("tool_transfer")
    if _out_of_scope_parameters(descriptor, parameter_names):
        findings.append("out_of_scope_parameter")

    return tuple(dict.fromkeys(findings))


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _matches(pattern: re.Pattern[str], text: str) -> bool:
    """Return whether ``pattern`` matches the raw text or a decoded variant."""
    return any(pattern.search(variant) for variant in _text_variants(text))


def _text_variants(text: str) -> tuple[str, ...]:
    """Return bounded descriptor text variants for poison-string rescans."""
    variants: list[str] = [text]
    normalised = unicodedata.normalize("NFKC", text)
    stripped = _ZERO_WIDTH.sub("", normalised)
    variants.extend([normalised, stripped])
    variants.append(codecs.decode(stripped, "rot_13"))
    for source in (text, normalised, stripped):
        for token in _BASE64_TOKEN.findall(source):
            decoded = _decode_base64_text(token)
            if decoded:
                variants.append(decoded)
                variants.append(codecs.decode(decoded, "rot_13"))
    return tuple(dict.fromkeys(variant for variant in variants if variant))


def _decode_base64_text(token: str) -> str:
    """Decode one base64 token into UTF-8 text for descriptor rescanning."""
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return ""
    if not raw or len(raw) > _MAX_DECODED_TEXT:
        return ""
    decoded = raw.decode("utf-8", errors="ignore")
    if not decoded.strip():
        return ""
    return decoded


def _discovery_text(descriptor: _DiscoveryDescriptor) -> str:
    return "\n".join(
        (
            descriptor.description,
            descriptor.instructions,
            _canonical(descriptor.input_schema),
            _canonical(descriptor.output_schema),
            _canonical(descriptor.argument_schema),
            _canonical(descriptor.hidden_metadata),
            _canonical(descriptor.remote_auth),
        )
    )


def _iter_schema_names(value: object) -> tuple[str, ...]:
    names: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                named_mapping = key in {"properties", "$defs", "definitions"}
                named_sequence = key in {"required", "dependentRequired"}
                if (named_mapping and isinstance(child, Mapping)) or (
                    named_sequence
                    and isinstance(child, Sequence)
                    and not isinstance(child, str)
                ):
                    names.extend(str(name) for name in child)
                visit(child)
        elif isinstance(node, Sequence) and not isinstance(node, str):
            for item in node:
                visit(item)

    visit(value)
    return tuple(dict.fromkeys(names))


def _iter_default_text(value: object) -> tuple[str, ...]:
    texts: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, Mapping):
            for key, child in node.items():
                if key in {"default", "const", "examples", "example", "enum"}:
                    texts.append(_canonical(child))
                visit(child)
        elif isinstance(node, Sequence) and not isinstance(node, str):
            for item in node:
                visit(item)

    visit(value)
    return tuple(texts)


def _parameter_names(descriptor: _DiscoveryDescriptor) -> tuple[str, ...]:
    names = [
        *_iter_schema_names(descriptor.input_schema),
        *_iter_schema_names(descriptor.argument_schema),
    ]
    return tuple(dict.fromkeys(name for name in names if name.strip()))


def _default_texts(descriptor: _DiscoveryDescriptor) -> tuple[str, ...]:
    return (
        *_iter_default_text(descriptor.input_schema),
        *_iter_default_text(descriptor.argument_schema),
    )


def _out_of_scope_parameters(
    descriptor: _DiscoveryDescriptor,
    parameter_names: tuple[str, ...],
) -> bool:
    if not _READ_TOOL.search(descriptor.tool):
        return False
    for name in parameter_names:
        normalised = name.strip().lower().replace("-", "_").replace(".", "_")
        if normalised in _READ_ALLOWED_PARAMETERS:
            continue
        if _MUTATING_PARAMETER.search(normalised):
            return True
    return False
