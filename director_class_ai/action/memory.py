# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — memory and long-horizon action metadata

"""Memory/write contracts and long-horizon drift detection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..core.signal import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    Plane,
    Severity,
)
from ._lexicon import MUTATING, MUTATING_TASK, UNTRUSTED_ORIGINS

__all__ = [
    "MEMORY_CONTEXT_KEY",
    "MemoryActionContext",
    "MemoryPlanDelta",
    "MemoryWriteContract",
    "MemoryThreatDetector",
]

MEMORY_CONTEXT_KEY = "memory_context"

_PERSISTENT_INJECTION = re.compile(
    r"\b(ignore|override|bypass|developer|system prompt|hidden instruction|"
    r"always remember|future tasks?|next time|persist(?:ent)? instruction)\b",
    re.IGNORECASE,
)
_DELAYED_OBJECTIVE = re.compile(
    r"\b(later|tomorrow|next session|after approval|after review|when asked|"
    r"eventually|defer(?:red)?)\b",
    re.IGNORECASE,
)
_SCHEMA_WORDS = re.compile(r"\b(schema|descriptor|tool registry|cached tool)\b", re.I)
_READONLY_GOAL = re.compile(
    r"\b(summarise|summarize|read|list|show|inspect|explain|review|extract)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class MemoryWriteContract:
    """Signed contract for a memory write or cached tool-schema update."""

    source: str
    tenant: str
    scope: str
    expires_at: int
    trust_tier: str
    allowed_retrieval_contexts: tuple[str, ...] = ()
    contract_digest: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> MemoryWriteContract:
        """Build a contract from JSON-like metadata."""
        contexts = value.get("allowed_retrieval_contexts")
        return cls(
            source=_string(value.get("source")),
            tenant=_string(value.get("tenant")),
            scope=_string(value.get("scope")),
            expires_at=_integer(value.get("expires_at")),
            trust_tier=_string(value.get("trust_tier")),
            allowed_retrieval_contexts=_string_tuple(contexts),
            contract_digest=_string(value.get("contract_digest")),
        )

    def signed(self) -> MemoryWriteContract:
        """Return a copy with a deterministic contract digest."""
        return MemoryWriteContract(
            source=self.source,
            tenant=self.tenant,
            scope=self.scope,
            expires_at=self.expires_at,
            trust_tier=self.trust_tier,
            allowed_retrieval_contexts=self.allowed_retrieval_contexts,
            contract_digest=_digest(
                {
                    "source": self.source,
                    "tenant": self.tenant,
                    "scope": self.scope,
                    "expires_at": self.expires_at,
                    "trust_tier": self.trust_tier,
                    "allowed_retrieval_contexts": self.allowed_retrieval_contexts,
                }
            ),
        )

    def is_valid_for(
        self,
        *,
        tenant: str,
        retrieval_context: str,
        now: int,
    ) -> bool:
        """Return whether this signed contract can influence retrieval now."""
        if (
            not self.contract_digest
            or self.signed().contract_digest != self.contract_digest
        ):
            return False
        if self.tenant != tenant:
            return False
        if self.expires_at and now and now > self.expires_at:
            return False
        if retrieval_context not in self.allowed_retrieval_contexts:
            return False
        return self.trust_tier.strip().lower() in {"trusted", "curated", "operator"}


@dataclass(frozen=True)
class MemoryPlanDelta:
    """Cross-turn comparison of goal, plan, retrieved context, and next action."""

    user_goal: str = ""
    current_plan: str = ""
    retrieved_context: str = ""
    proposed_next_action: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> MemoryPlanDelta:
        """Build a plan delta from JSON-like metadata."""
        return cls(
            user_goal=_string(value.get("user_goal")),
            current_plan=_string(value.get("current_plan")),
            retrieved_context=_string(value.get("retrieved_context")),
            proposed_next_action=_string(value.get("proposed_next_action")),
        )

    def as_mapping(self) -> Mapping[str, str]:
        """Return the JSON-ready plan-delta representation."""
        return {
            "user_goal": self.user_goal,
            "current_plan": self.current_plan,
            "retrieved_context": self.retrieved_context,
            "proposed_next_action": self.proposed_next_action,
        }


@dataclass(frozen=True)
class MemoryActionContext:
    """Runtime metadata for memory and long-horizon action review."""

    tenant: str
    retrieval_context: str
    now: int = 0
    contract: MemoryWriteContract | None = None
    plan_delta: MemoryPlanDelta = field(default_factory=MemoryPlanDelta)
    cached_schema_digest: str = ""
    live_schema_digest: str = ""
    memory_text: str = ""
    memory_source: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> MemoryActionContext:
        """Build memory review metadata from a JSON-like mapping."""
        contract = value.get("contract")
        delta = value.get("plan_delta")
        return cls(
            tenant=_string(value.get("tenant")),
            retrieval_context=_string(value.get("retrieval_context")),
            now=_integer(value.get("now")),
            contract=(
                MemoryWriteContract.from_mapping(contract)
                if isinstance(contract, Mapping)
                else None
            ),
            plan_delta=(
                MemoryPlanDelta.from_mapping(delta)
                if isinstance(delta, Mapping)
                else MemoryPlanDelta()
            ),
            cached_schema_digest=_string(value.get("cached_schema_digest")),
            live_schema_digest=_string(value.get("live_schema_digest")),
            memory_text=_string(value.get("memory_text")),
            memory_source=_string(value.get("memory_source")),
        )

    def as_metadata(self) -> Mapping[str, object]:
        """Return JSON-ready metadata for evaluation requests."""
        return {
            "tenant": self.tenant,
            "retrieval_context": self.retrieval_context,
            "now": self.now,
            "contract": (
                self.contract.signed().__dict__ if self.contract is not None else {}
            ),
            "plan_delta": dict(self.plan_delta.as_mapping()),
            "cached_schema_digest": self.cached_schema_digest,
            "live_schema_digest": self.live_schema_digest,
            "memory_text": self.memory_text,
            "memory_source": self.memory_source,
        }


class MemoryThreatDetector:
    """Tier-0 detector for memory poisoning and long-horizon action drift."""

    name = "memory_threat"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
        """Return a signal when memory state changes a later action route."""
        raw = request.metadata.get(MEMORY_CONTEXT_KEY)
        if isinstance(raw, MemoryActionContext):
            context = raw
        elif isinstance(raw, Mapping):
            context = MemoryActionContext.from_mapping(raw)
        else:
            return None

        invalid = _invalid_contract(context)
        if invalid:
            return _signal(
                "memory_poisoning",
                Severity.HIGH,
                f"memory contract rejected: {invalid}",
            )
        if _stale_schema(context):
            return _signal(
                "stale_tool_schema",
                Severity.HIGH,
                "cached tool schema digest differs from the live schema digest",
            )
        if _persistent_instruction(context):
            return _signal(
                "persistent_instruction_injection",
                Severity.HIGH,
                "memory text attempts to install persistent action instructions",
            )
        if _delayed_objective(context):
            return _signal(
                "delayed_malicious_objective",
                Severity.HIGH,
                "memory text carries a delayed objective into a later action",
            )
        if _plan_drift(context, request):
            return _signal(
                "task_plan_drift",
                Severity.HIGH,
                "plan delta changes a read-only user goal into a mutating action",
            )
        return None


def _invalid_contract(context: MemoryActionContext) -> str:
    contract = context.contract
    if contract is None:
        return "missing_contract"
    if not contract.is_valid_for(
        tenant=context.tenant,
        retrieval_context=context.retrieval_context,
        now=context.now,
    ):
        return "invalid_or_expired_contract"
    if context.memory_source.strip().lower() in UNTRUSTED_ORIGINS:
        return "untrusted_memory_source"
    return ""


def _stale_schema(context: MemoryActionContext) -> bool:
    return bool(
        context.cached_schema_digest
        and context.live_schema_digest
        and context.cached_schema_digest != context.live_schema_digest
        and _SCHEMA_WORDS.search(context.plan_delta.retrieved_context)
    )


def _persistent_instruction(context: MemoryActionContext) -> bool:
    return bool(_PERSISTENT_INJECTION.search(context.memory_text))


def _delayed_objective(context: MemoryActionContext) -> bool:
    text = f"{context.memory_text}\n{context.plan_delta.retrieved_context}"
    return bool(_DELAYED_OBJECTIVE.search(text) and MUTATING.search(text))


def _plan_drift(context: MemoryActionContext, request: EvaluationRequest) -> bool:
    delta = context.plan_delta
    proposed = delta.proposed_next_action or request.action
    if not proposed or not MUTATING.search(proposed):
        return False
    goal = delta.user_goal or request.query
    if MUTATING_TASK.search(goal):
        return False
    if not _READONLY_GOAL.search(goal):
        return False
    plan_text = f"{delta.current_plan}\n{delta.retrieved_context}"
    return bool(MUTATING.search(plan_text) or proposed.casefold() in plan_text.casefold())


def _signal(signal_type: str, severity: Severity, rationale: str) -> DetectorSignal:
    return DetectorSignal(
        detector="memory_threat",
        plane=Plane.ACTION,
        score=0.88,
        locus=Locus.ACTION,
        signal_type=signal_type,
        severity=severity,
        rationale=rationale,
    )


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _integer(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0


def _string(value: object) -> str:
    return "" if value is None else str(value)


def _string_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, str):
        return tuple(str(item) for item in value)
    return ()
