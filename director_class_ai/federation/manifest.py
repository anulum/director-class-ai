# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — schema-A studio capability manifest producer (GOVERN layer)

"""Build the Director-Class AI schema-A studio capability manifest.

The federation-gate artifact the SCPN-STUDIO keeper and the Director family portal
consume for the **GOVERN** layer of the trust stack — the schema-A manifest
(locked contract era ``v1``) carrying the studio's action-governance ``verbs``,
``evidence_types``, federated ``ui_module``, and a deterministic ``content_digest``.
It pairs with Director-AI's DETECT-layer manifest: a portal reads both (never the
Python internals) to render the ``detect → govern → operate`` pipeline.

The producer is self-contained — it emits a schema-A-conformant mapping directly,
with no dependency on the (not-yet-published) ``scpn-studio-platform`` SDK.

Verbs are the **action-governance** domain's, grounded in shipped capabilities:
policy/capability ``gate``, action-risk ``assess`` (blast radius, reversibility,
destructive/causal-takeover analysis), ``approve`` (queue + human escalation),
crash-durable ``audit`` chains, the ``detect`` suite, ``actuate`` (the effectors
that run a real action), ``certify`` (capability profiles), and ``benchmark``.

``safety_tier`` and ``side_effect`` are honest per the repo's own bounded
claim-language (``positioning.py``): runtime action-control, escalation, and audit
are evidenced today → ``production``; the real-executor ``actuate`` path is
``certified`` and carries ``side_effect: live-hardware`` (the hub hard-gates it,
contract §2.3 — never actuate a production binding without a certified controller);
comparative ``benchmark`` advantage and external ``certify`` work are *blocked*
claims, so those verbs are honestly ``research``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version

__all__ = [
    "CONTRACT_ERA",
    "StudioManifest",
    "UiModule",
    "Verb",
    "build_manifest",
]

#: The locked studio network-contract era this manifest pins (see the v1 contract).
CONTRACT_ERA = "v1"

#: SYNAPSE wire-protocol axis, versioned independently of the contract era.
PROTOCOL_VERSION = "1"

#: Director-Class AI runs the free local-first profile; tenant identity is ignored.
TRANSPORT_PROFILE = "local-first"

#: SemVer range of the platform SDK this manifest targets once it is published.
PLATFORM_SDK = ">=0.1,<0.2"

#: Studio slug; stable identity across versions.
STUDIO = "director-class-ai"


@dataclass(frozen=True)
class Verb:
    """One capability verb the studio exposes, with its contract attributes."""

    verb: str
    safety_tier: str
    side_effect: str
    timing_class: str
    produces: tuple[str, ...]
    backends: tuple[str, ...]
    fidelity: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Render the verb as a sorted-key-ready schema-A mapping."""
        payload: dict[str, object] = {
            "verb": self.verb,
            "safety_tier": self.safety_tier,
            "side_effect": self.side_effect,
            "timing": {"class": self.timing_class},
            "produces": list(self.produces),
            "backends": list(self.backends),
        }
        if self.fidelity is not None:
            payload["fidelity"] = self.fidelity
        return payload


@dataclass(frozen=True)
class UiModule:
    """The federated UI panel descriptor (Module Federation 2.x)."""

    remote_entry: str
    exposes: tuple[str, ...]
    federation: str = "module-federation-2"

    def to_dict(self) -> dict[str, object]:
        """Render the ui_module as a schema-A mapping."""
        return {
            "remote_entry": self.remote_entry,
            "exposes": list(self.exposes),
            "federation": self.federation,
        }


# The action-governance verb registry — each grounded in a shipped capability,
# each tier/side-effect honest per positioning.py's bounded claim-language.
_VERBS: tuple[Verb, ...] = (
    Verb(
        verb="gate",
        safety_tier="production",
        side_effect="read-only",
        timing_class="interactive",
        produces=("studio.action-decision.v1",),
        backends=("python", "rust"),
    ),
    Verb(
        verb="assess",
        safety_tier="production",
        side_effect="read-only",
        timing_class="interactive",
        produces=("studio.action-risk.v1",),
        backends=("python", "rust"),
    ),
    Verb(
        verb="approve",
        safety_tier="production",
        side_effect="read-only",
        timing_class="interactive",
        produces=("studio.approval-record.v1",),
        backends=("python",),
    ),
    Verb(
        verb="audit",
        safety_tier="production",
        side_effect="read-only",
        timing_class="batch",
        produces=("studio.audit-chain.v1",),
        backends=("python", "rust"),
    ),
    Verb(
        verb="detect",
        safety_tier="production",
        side_effect="read-only",
        timing_class="interactive",
        produces=("studio.detector-scan.v1",),
        backends=("python", "rust"),
    ),
    Verb(
        verb="actuate",
        safety_tier="certified",
        side_effect="live-hardware",
        timing_class="realtime",
        produces=("studio.action-execution.v1",),
        backends=("python",),
    ),
    Verb(
        verb="certify",
        safety_tier="research",
        side_effect="read-only",
        timing_class="batch",
        produces=("studio.capability-profile.v1",),
        backends=("python",),
    ),
    Verb(
        verb="benchmark",
        safety_tier="research",
        side_effect="simulated",
        timing_class="batch",
        produces=("studio.action-benchmark.v1",),
        backends=("python",),
    ),
)

_UI_MODULE = UiModule(
    remote_entry="/studio/remoteEntry.js",
    exposes=("./DirectorClassStudioPanel",),
)


def _studio_version() -> str:
    """Return the installed distribution version, or a source-tree sentinel.

    The version is an environment-dependent stamp (installed dist vs a source
    checkout); the ``--check`` drift gate excludes it so the check is env-stable,
    while ``content_digest`` covers the verb/evidence contract that must not drift.
    """
    try:
        return version("director-class-ai")
    except PackageNotFoundError:
        return "0+unknown"


@dataclass(frozen=True)
class StudioManifest:
    """The schema-A capability manifest for the Director-Class AI studio.

    Serialises (via :meth:`to_dict`) to the deterministic, sorted-key JSON the
    federation gate consumes. ``content_digest`` is computed over the contract
    body (every field except the digest itself and the environment-dependent
    ``studio_version``), so any verb, evidence-type, or ui_module change moves the
    digest and trips the drift gate, while a version bump alone does not.
    """

    verbs: tuple[Verb, ...]
    ui_module: UiModule
    studio_version: str = field(default_factory=_studio_version)

    @property
    def evidence_types(self) -> tuple[str, ...]:
        """Sorted, de-duplicated set of evidence schemas the verbs produce."""
        seen: set[str] = set()
        for verb in self.verbs:
            seen.update(verb.produces)
        return tuple(sorted(seen))

    def _contract_body(self) -> dict[str, object]:
        """Return the digest-covered contract fields (no digest, no version)."""
        return {
            "contract_era": CONTRACT_ERA,
            "protocol_version": PROTOCOL_VERSION,
            "transport_profile": TRANSPORT_PROFILE,
            "studio": STUDIO,
            "platform_sdk": PLATFORM_SDK,
            "enumeration": "language-agnostic",
            "evidence_types": list(self.evidence_types),
            "verbs": [verb.to_dict() for verb in self.verbs],
            "ui_module": self.ui_module.to_dict(),
        }

    def content_digest(self) -> str:
        """Return the deterministic ``sha256:`` digest of the contract body."""
        canonical = json.dumps(
            self._contract_body(),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Render the full schema-A manifest (contract body + digest + version)."""
        payload = self._contract_body()
        payload["content_digest"] = self.content_digest()
        payload["studio_version"] = self.studio_version
        return payload


def build_manifest() -> StudioManifest:
    """Build the Director-Class AI schema-A studio capability manifest."""
    return StudioManifest(verbs=_VERBS, ui_module=_UI_MODULE)
