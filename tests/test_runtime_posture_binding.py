# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — runtime posture binding tests

"""The approved Guardrail-as-Code head must actually govern runtime decisions.

These tests prove the bridge end to end: an approved posture is resolved into a
fusion policy, the policy is forwarded to the runtime ensemble, and changing the
approved posture demonstrably flips the ensemble's decision on the same input.
"""

from __future__ import annotations

from pathlib import Path

from director_class_ai.action import MCPToolRegistration
from director_class_ai.cli.guard import (
    CommandGuardOptions,
    _resolve_runtime_policy,
    run_guard,
)
from director_class_ai.core.fusion import FusionPolicy
from director_class_ai.core.signal import DetectorSignal, Locus, Plane, Severity
from director_class_ai.gateway import MCPGateway, MCPGatewayRequest
from director_class_ai.policy import (
    BlastRadius,
    CapabilityContext,
    CapabilityGrant,
    PolicyGovernance,
    Profile,
    resolve_runtime_posture,
)
from director_class_ai.sdk import ToolReviewMiddleware, ToolReviewRequest


class _FixedActionDetector:
    """A detector that emits one action-plane objection at a fixed score."""

    name = "fixture"
    plane = Plane.ACTION
    tier = 0

    def __init__(self, score: float) -> None:
        self._score = score

    def evaluate(self, request: object) -> DetectorSignal:
        return DetectorSignal(
            detector="fixture",
            plane=Plane.ACTION,
            score=self._score,
            locus=Locus.ACTION,
            signal_type="generic_mutation",
            severity=Severity.MEDIUM,
        )


def _route(policy: FusionPolicy | None) -> str:
    middleware = ToolReviewMiddleware.default(
        detectors=[_FixedActionDetector(0.5)], policy=policy
    )
    decision = middleware.review(
        ToolReviewRequest(tool_name="x", action="mutate", provenance="")
    )
    if decision.escalated:
        return "human"
    return "allow" if decision.permitted else "block"


def _approved_ledger(
    path: Path,
    *,
    action_block_threshold: float = 0.3,
    uncertainty_margin: float = 0.05,
    capability_profile: str = "deny_all_actions",
) -> Profile:
    governance = PolicyGovernance.load(str(path))
    profile = Profile(
        name="staging",
        action_block_threshold=action_block_threshold,
        uncertainty_margin=uncertainty_margin,
        capability_profile=capability_profile,
    )
    proposal = governance.propose(
        profile, proposer="alice", created_at="t0", reason="set posture"
    )
    governance.approve(proposal.digest, reviewer="bob", decided_at="t1")
    governance.save(str(path))
    return profile


def _registration() -> MCPToolRegistration:
    return MCPToolRegistration(
        server="fs",
        tool="read_file",
        server_identity={"name": "fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema={"properties": {"path": {"type": "string"}}},
    )


def _capability_grant() -> CapabilityGrant:
    return CapabilityGrant(
        grant_id="read-workspace",
        subject="agent-a",
        tenant="tenant-a",
        session="session-a",
        source_origin="user",
        tool="fs/read_file",
        resource="workspace:README.md",
        action="read",
        max_blast_radius=BlastRadius.LOW,
    )


def _mcp_request() -> MCPGatewayRequest:
    return MCPGatewayRequest.from_parts(
        "fs",
        "read_file",
        {"path": "README.md"},
        server_identity={"name": "fs", "transport": "stdio"},
        tool_schema={"description": "Read one workspace file", "mode": "read"},
        argument_schema={"properties": {"path": {"type": "string"}}},
        capability_context={
            "subject": "agent-a",
            "tenant": "tenant-a",
            "session": "session-a",
            "source_origin": "user",
            "tool": "fs/read_file",
            "resource": "workspace:README.md",
            "action": "read",
            "blast_radius": "low",
        },
        provenance="user",
    )


class TestMiddlewarePolicyBinding:
    def test_policy_governs_the_decision(self) -> None:
        strict = FusionPolicy(action_block_threshold=0.3, uncertainty_margin=0.0)
        relaxed = FusionPolicy(action_block_threshold=0.7, uncertainty_margin=0.0)
        assert _route(strict) == "block"
        assert _route(relaxed) == "allow"

    def test_no_policy_keeps_the_failclosed_default(self) -> None:
        # the default action_block_threshold (0.3) blocks a 0.5 action objection
        assert _route(None) == "block"


class TestGovernanceToPolicyBridge:
    def test_no_approved_head_yields_no_policy(self) -> None:
        assert PolicyGovernance.empty().active_fusion_policy() is None

    def test_approved_head_yields_its_fusion_policy(self, tmp_path: Path) -> None:
        store = tmp_path / "policy.json"
        profile = _approved_ledger(
            store, action_block_threshold=0.7, uncertainty_margin=0.0
        )
        active = PolicyGovernance.load(str(store)).active_fusion_policy()
        assert active == profile.to_fusion_policy()

    def test_matching_live_profile_does_not_emit_runtime_drift(
        self, tmp_path: Path
    ) -> None:
        store = tmp_path / "policy.json"
        _approved_ledger(store, action_block_threshold=0.7, uncertainty_margin=0.0)
        live = tmp_path / "live.toml"
        live.write_text(
            'name = "staging"\n'
            "action_block_threshold = 0.7\n"
            "uncertainty_margin = 0.0\n"
            'capability_profile = "deny_all_actions"\n',
            encoding="utf-8",
        )

        posture = resolve_runtime_posture(
            str(store),
            live_profile=live,
            detected_at="t2",
        )

        assert posture.blocked is False
        assert posture.drift_event is None

    def test_approved_head_yields_its_capability_policy(self, tmp_path: Path) -> None:
        store = tmp_path / "policy.json"
        _approved_ledger(store, capability_profile="local_operator_actions")
        governance = PolicyGovernance.load(str(store))

        active = governance.active_capability_policy(grants=(_capability_grant(),))

        assert active is not None
        decision = active.evaluate(
            CapabilityContext.from_mapping(_mcp_request().capability_context)
        )
        assert decision.permitted is True


class TestGuardPolicyResolution:
    def test_absent_ledger_resolves_to_none(self, tmp_path: Path) -> None:
        assert _resolve_runtime_policy(str(tmp_path / "absent.json")) is None

    def test_approved_head_is_resolved_for_the_guard(self, tmp_path: Path) -> None:
        store = tmp_path / "policy.json"
        profile = _approved_ledger(store, action_block_threshold=0.7)
        assert _resolve_runtime_policy(str(store)) == profile.to_fusion_policy()

    def test_run_guard_uses_the_approved_posture(self, tmp_path: Path) -> None:
        store = tmp_path / "policy.json"
        _approved_ledger(store, action_block_threshold=0.7, uncertainty_margin=0.0)
        event = run_guard(
            CommandGuardOptions(
                surface="shell",
                command=("echo", "ok"),
                audit_log=str(tmp_path / "audit.jsonl"),
                approval_store=str(tmp_path / "approvals.json"),
                policy_store=str(store),
            )
        )
        assert _resolve_runtime_policy(str(store)) is not None
        assert event["permitted"] is True


class TestMCPGatewayPolicyBinding:
    def test_gateway_factory_uses_approved_capability_head(self, tmp_path: Path) -> None:
        store = tmp_path / "policy.json"
        _approved_ledger(store, capability_profile="local_operator_actions")

        without_ledger = MCPGateway.from_registry(
            [_registration()],
            capability_policy=Profile(name="default").to_capability_policy(
                (_capability_grant(),)
            ),
        ).review(_mcp_request())
        with_ledger = MCPGateway.from_policy_store(
            [_registration()],
            store,
            capability_grants=(_capability_grant(),),
        ).review(_mcp_request())

        assert without_ledger.route == "block"
        assert with_ledger.route == "allow"
