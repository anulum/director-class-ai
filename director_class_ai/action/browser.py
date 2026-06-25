# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — browser and computer-use action metadata

"""Browser/computer-use metadata and detector for action-plane governance."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)

__all__ = [
    "BROWSER_ACTION_KEY",
    "BrowserAction",
    "BrowserActionDetector",
    "BrowserWorkLog",
    "BrowserWorkLogEntry",
    "ComputerAction",
]

BROWSER_ACTION_KEY = "browser_action"

_INJECTION = re.compile(
    r"\b(ignore|override|bypass|developer|system prompt|hidden instruction|"
    r"always click|always call|exfiltrat(?:e|ion)|send private data)\b",
    re.IGNORECASE,
)
_HIJACK = re.compile(
    r"\b(allow notifications|download required|security warning|session expired|"
    r"verify wallet|urgent update|continue to prize)\b",
    re.IGNORECASE,
)
_MUTATING = re.compile(
    r"\b(click|submit|send|post|upload|download|paste|copy|fill|approve|pay|"
    r"transfer|delete|create|update|install|open)\b",
    re.IGNORECASE,
)
_UNSAFE_DOWNLOAD = re.compile(
    r"\.(?:exe|msi|dmg|pkg|app|sh|bash|zsh|ps1|bat|cmd|scr|jar)$",
    re.IGNORECASE,
)
_SENSITIVE_CATEGORIES = frozenset(
    {
        "banking",
        "healthcare",
        "identity",
        "production_admin",
        "source_control",
        "payment",
    }
)


@dataclass(frozen=True)
class BrowserAction:
    """Evidence envelope for one browser or computer-use action."""

    page_origin: str = ""
    frame_origin: str = ""
    selected_element: str = ""
    visible_text: str = ""
    hidden_text: str = ""
    screenshot_digest: str = ""
    target_url: str = ""
    form_fields: Mapping[str, str] = field(default_factory=dict)
    download_path: str = ""
    clipboard_mutation: str = ""
    sensitive_site_category: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> BrowserAction:
        """Build metadata from JSON-like browser action evidence."""
        fields = value.get("form_fields")
        return cls(
            page_origin=_string(value.get("page_origin")),
            frame_origin=_string(value.get("frame_origin")),
            selected_element=_string(value.get("selected_element")),
            visible_text=_string(value.get("visible_text")),
            hidden_text=_string(value.get("hidden_text")),
            screenshot_digest=_string(value.get("screenshot_digest")),
            target_url=_string(value.get("target_url")),
            form_fields=_string_mapping(fields),
            download_path=_string(value.get("download_path")),
            clipboard_mutation=_string(value.get("clipboard_mutation")),
            sensitive_site_category=_string(value.get("sensitive_site_category")),
        )

    def as_metadata(self) -> Mapping[str, object]:
        """Return a JSON-ready metadata mapping for evaluation requests."""
        return {
            "page_origin": self.page_origin,
            "frame_origin": self.frame_origin,
            "selected_element": self.selected_element,
            "visible_text": self.visible_text,
            "hidden_text": self.hidden_text,
            "screenshot_digest": self.screenshot_digest,
            "target_url": self.target_url,
            "form_fields": dict(self.form_fields),
            "download_path": self.download_path,
            "clipboard_mutation": self.clipboard_mutation,
            "sensitive_site_category": self.sensitive_site_category,
        }


class ComputerAction(BrowserAction):
    """Computer-use action evidence using the browser action envelope."""


@dataclass(frozen=True)
class BrowserWorkLogEntry:
    """Redacted browser/computer-use action entry for operator review."""

    action_label: str
    route: str
    origins_touched: tuple[str, ...]
    approvals: tuple[str, ...]
    blocks: tuple[str, ...]
    evidence_digests: tuple[str, ...]

    @classmethod
    def from_action(
        cls,
        action: BrowserAction,
        *,
        action_label: str,
        route: str,
        firing: Sequence[str] = (),
    ) -> BrowserWorkLogEntry:
        """Build a redacted entry without raw text, form values, or clipboard data."""
        origins = tuple(
            origin
            for origin in (
                _origin(action.page_origin),
                _origin(action.frame_origin),
                _origin(action.target_url),
            )
            if origin
        )
        approvals = tuple(signal for signal in firing if signal.endswith("_approval"))
        blocks = tuple(signal for signal in firing if signal not in approvals)
        digest_inputs = (
            action.screenshot_digest,
            _download_digest(action.download_path),
        )
        digests = tuple(value for value in digest_inputs if value)
        return cls(
            action_label=action_label,
            route=route,
            origins_touched=tuple(dict.fromkeys(origins)),
            approvals=approvals,
            blocks=blocks,
            evidence_digests=digests,
        )

    def as_mapping(self) -> Mapping[str, object]:
        """Return a JSON-ready redacted work-log entry."""
        return {
            "action_label": self.action_label,
            "route": self.route,
            "origins_touched": self.origins_touched,
            "approvals": self.approvals,
            "blocks": self.blocks,
            "evidence_digests": self.evidence_digests,
        }


@dataclass(frozen=True)
class BrowserWorkLog:
    """Redacted work-log export for browser/computer-use sessions."""

    task: str
    entries: tuple[BrowserWorkLogEntry, ...]

    def as_mapping(self) -> Mapping[str, object]:
        """Return a JSON-ready log without raw visible text or field values."""
        return {
            "task": self.task,
            "origins_touched": tuple(
                dict.fromkeys(
                    origin for entry in self.entries for origin in entry.origins_touched
                )
            ),
            "actions_attempted": tuple(entry.action_label for entry in self.entries),
            "approvals": tuple(
                signal for entry in self.entries for signal in entry.approvals
            ),
            "blocks": tuple(signal for entry in self.entries for signal in entry.blocks),
            "evidence_digests": tuple(
                dict.fromkeys(
                    digest for entry in self.entries for digest in entry.evidence_digests
                )
            ),
            "entries": tuple(entry.as_mapping() for entry in self.entries),
        }


class BrowserActionDetector:
    """Tier-0 action detector for browser and computer-use risks."""

    name = "browser_action"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Return the highest-priority browser/computer-use signal."""
        raw = request.metadata.get(BROWSER_ACTION_KEY)
        if isinstance(raw, BrowserAction):
            action = raw
        elif isinstance(raw, Mapping):
            action = BrowserAction.from_mapping(raw)
        else:
            return None

        command = request.action or ""
        if action.hidden_text and _INJECTION.search(action.hidden_text):
            return _signal(
                "browser_prompt_injection",
                Severity.HIGH,
                "hidden browser text contains action-steering instructions",
            )
        if _cross_origin_frame(action) and _MUTATING.search(command):
            return _signal(
                "browser_malicious_iframe",
                Severity.HIGH,
                "mutating browser action targets a cross-origin frame",
            )
        if _HIJACK.search(" ".join((action.selected_element, action.visible_text))):
            return _signal(
                "browser_popup_hijack",
                Severity.HIGH,
                "visible browser element matches pop-up or tool-hijack pattern",
            )
        if action.clipboard_mutation and _external_target(action):
            return _signal(
                "browser_clipboard_exfiltration",
                Severity.HIGH,
                "clipboard mutation is paired with an external target",
            )
        if action.download_path and _UNSAFE_DOWNLOAD.search(action.download_path):
            return _signal(
                "browser_unsafe_download",
                Severity.HIGH,
                "browser action downloads an executable or script payload",
            )
        if action.form_fields and _cross_origin_target(action):
            return _signal(
                "browser_cross_site_task_drift",
                Severity.HIGH,
                "form submission crosses away from the visible page origin",
            )
        if (
            action.sensitive_site_category.strip().lower() in _SENSITIVE_CATEGORIES
            and _MUTATING.search(command)
        ):
            return _signal(
                "browser_sensitive_site_approval",
                Severity.HIGH,
                "sensitive-site action requires human approval",
            )
        return None


def _signal(signal_type: str, severity: Severity, rationale: str) -> DetectorSignal:
    return DetectorSignal(
        detector="browser_action",
        plane=Plane.ACTION,
        score=0.82,
        locus=Locus.ACTION,
        signal_type=signal_type,
        severity=severity,
        rationale=rationale,
    )


def _origin(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".lower()
    return value.strip().lower().rstrip("/")


def _cross_origin_frame(action: BrowserAction) -> bool:
    return bool(
        action.page_origin
        and action.frame_origin
        and _origin(action.page_origin) != _origin(action.frame_origin)
    )


def _cross_origin_target(action: BrowserAction) -> bool:
    return bool(
        action.page_origin
        and action.target_url
        and _origin(action.page_origin) != _origin(action.target_url)
    )


def _external_target(action: BrowserAction) -> bool:
    target = _origin(action.target_url)
    page = _origin(action.page_origin)
    return bool(target and page and target != page)


def _download_digest(value: str) -> str:
    if not value:
        return ""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"path-digest:{digest}"


def _string(value: object) -> str:
    return "" if value is None else str(value)


def _string_mapping(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}
