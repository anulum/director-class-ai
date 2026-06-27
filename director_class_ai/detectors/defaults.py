# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — dependency-light default detectors

"""Dependency-light content and integrity detectors for default runtime paths."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass

from ..core import Detector
from .injection import InjectionField, InjectionPromptDetector
from .pii import PIIContentDetector

__all__ = ["default_content_integrity_detectors"]

_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff]")
_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])"
)
_MAX_DECODED_TEXT = 4096
_INJECTION_PATTERNS = (
    re.compile(
        r"\b("
        r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|task|rules)|"
        r"system\s+prompt|"
        r"developer\s+message|"
        r"hidden\s+instruction|"
        r"jailbreak|"
        r"bypass\s+(?:policy|approval|review)|"
        r"reveal\s+(?:credentials?|secrets?)|"
        r"send\s+(?:credentials?|secrets?)"
        r")\b",
        re.IGNORECASE,
    ),
)
_PII_PATTERNS = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE)),
)


@dataclass(frozen=True)
class _DefaultInjectionResult:
    """Prompt-injection screening result for the default regex backend."""

    blocked: bool
    score: float
    stage: str
    reason: str


class _DefaultInjectionBackend:
    """Dependency-light prompt-injection screen over decoded text variants."""

    def screen(self, text: str) -> _DefaultInjectionResult:
        """Return the first matching prompt-injection finding for ``text``."""
        for variant in _text_variants(text):
            if any(pattern.search(variant) for pattern in _INJECTION_PATTERNS):
                return _DefaultInjectionResult(
                    blocked=True,
                    score=0.95,
                    stage="default_regex",
                    reason="instruction takeover pattern",
                )
        return _DefaultInjectionResult(
            blocked=False,
            score=0.0,
            stage="default_regex",
            reason="no match",
        )


@dataclass(frozen=True)
class _DefaultPIIMatch:
    """One regex PII finding for the default moderation backend."""

    category: str
    start: int
    end: int
    score: float


@dataclass(frozen=True)
class _DefaultPIIResult:
    """PII moderation result for the default regex backend."""

    matches: tuple[_DefaultPIIMatch, ...]


class _DefaultPIIBackend:
    """Dependency-light PII scanner for generated responses."""

    def analyse(self, text: str) -> _DefaultPIIResult:
        """Return regex PII matches for ``text``."""
        matches: list[_DefaultPIIMatch] = []
        for category, pattern in _PII_PATTERNS:
            matches.extend(
                _DefaultPIIMatch(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    score=0.99,
                )
                for match in pattern.finditer(text)
            )
        return _DefaultPIIResult(tuple(matches))


def default_content_integrity_detectors(
    *,
    include_response: bool = True,
) -> tuple[Detector, ...]:
    """Return the dependency-light content/integrity default detector set.

    Parameters
    ----------
    include_response:
        When true, generated responses are scanned for prompt injection and PII.
        Set to false for pre-response boundaries that should only inspect query
        and context integrity.
    """
    injection_fields: Sequence[InjectionField]
    if include_response:
        injection_fields = ("query", "context", "response")
    else:
        injection_fields = ("query", "context")
    detectors: list[Detector] = [
        InjectionPromptDetector(
            _DefaultInjectionBackend(),
            fields=injection_fields,
            threshold=0.5,
        ),
    ]
    if include_response:
        detectors.append(PIIContentDetector(_DefaultPIIBackend(), field="response"))
    return tuple(detectors)


def _text_variants(text: str) -> tuple[str, ...]:
    variants: list[str] = [text]
    normalised = unicodedata.normalize("NFKC", text)
    stripped = _ZERO_WIDTH.sub("", normalised)
    variants.extend([normalised, stripped, codecs.decode(stripped, "rot_13")])
    for source in (text, normalised, stripped):
        for token in _BASE64_TOKEN.findall(source):
            decoded = _decode_base64_text(token)
            if decoded:
                variants.extend([decoded, codecs.decode(decoded, "rot_13")])
    return tuple(dict.fromkeys(variant for variant in variants if variant))


def _decode_base64_text(token: str) -> str:
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return ""
    if not raw or len(raw) > _MAX_DECODED_TEXT:
        return ""
    decoded = raw.decode("utf-8", errors="ignore")
    return decoded if decoded.strip() else ""
