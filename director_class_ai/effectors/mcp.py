# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — MCP effector adapter

"""A governed Model Context Protocol effector.

Every MCP tool call an agent proposes is taken through the Governor before the
real tool runs. Unlike the shell adapter, the executor is *structured* — it
receives the :class:`MCPToolCall`, not a flattened string — because that is what
an MCP client actually dispatches. The call is also serialised into the request's
action string (so the destructive-command / blast-radius detectors see destructive
argument payloads) and carried whole in ``metadata`` (so :class:`MCPCallInspector`
sees the argument-granular structure). Dry-run is the default: nothing dispatches
until a deployment explicitly opts in, and a blocked or unapproved-escalated call
never reaches the executor.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from ..action.mcp_inspector import MCP_CALL_KEY, MCPToolCall, serialise_call
from ..core.governor import Governor
from .types import (
    EffectorKind,
    EffectorRequest,
    EffectorResult,
    GovernedEffector,
    _executed_result,
)

__all__ = ["MCPEffectorAdapter", "MCPExecuteFn"]

# A structured MCP executor: dispatch a tool call, return (output_text, exit_code).
# Only ever called for a permitted, non-dry-run request.
MCPExecuteFn = Callable[[MCPToolCall], tuple[str, int]]


class MCPEffectorAdapter(GovernedEffector):
    """Governed MCP effector. ``execute`` is injected; absent ⇒ dry-run only."""

    kind = EffectorKind.MCP

    def __init__(self, governor: Governor, execute: MCPExecuteFn | None = None) -> None:
        super().__init__(governor, None)
        self._mcp_execute = execute

    def call_tool(
        self,
        server: str,
        tool: str,
        arguments: Mapping[str, object] | None = None,
        *,
        arg_provenance: Mapping[str, str] | None = None,
        server_identity: Mapping[str, object] | None = None,
        tool_schema: Mapping[str, object] | None = None,
        argument_schema: Mapping[str, object] | None = None,
        provenance: str = "",
        query: str = "",
        context: str = "",
        dry_run: bool = True,
    ) -> EffectorResult:
        call = MCPToolCall(
            server=server,
            tool=tool,
            arguments=dict(arguments or {}),
            arg_provenance=dict(arg_provenance or {}),
            default_provenance=provenance,
            server_identity=dict(server_identity or {}),
            tool_schema=dict(tool_schema or {}),
            argument_schema=dict(argument_schema or {}),
        )
        request = EffectorRequest(
            action=serialise_call(call),
            kind=EffectorKind.MCP,
            provenance=provenance,
            query=query,
            context=context,
            dry_run=dry_run,
            metadata={MCP_CALL_KEY: call},
        )
        return self.run_call(call, request)

    def run_call(self, call: MCPToolCall, request: EffectorRequest) -> EffectorResult:
        """Govern a pre-built structured call, dispatching via the typed executor."""
        decision = self._governor.review(request.to_evaluation())
        if not decision.permitted or request.dry_run or self._mcp_execute is None:
            return EffectorResult(
                permitted=decision.permitted, executed=False, decision=decision
            )
        output, exit_code = self._mcp_execute(call)
        return _executed_result(decision, output, exit_code)
