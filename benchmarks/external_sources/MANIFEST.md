<!-- SPDX-License-Identifier: BUSL-1.1 -->
<!-- Director-Class AI - external benchmark source manifest -->
<!-- (c) Concepts 1996-2026 Miroslav Sotek. All rights reserved. -->
<!-- (c) Code 2020-2026 Miroslav Sotek. All rights reserved. -->
<!-- ORCID: 0009-0009-3560-0851 -->
<!-- Contact: www.anulum.li | protoscience@anulum.li -->
<!-- Internal benchmark provenance manifest; not claim-grade evidence. -->

# External Action Surfaces

This manifest lists external-style benchmark surfaces that may be imported into
the action-plane benchmark only when the corresponding local JSONL artefact is
present. Missing artefacts are skipped and recorded as not loaded; no examples are
fabricated from benchmark names.

`SOURCE_LEDGER.json` is the structured licence/provenance gate. A present local
JSONL artefact is rejected unless its surface has a matching source-review row
with `import_allowed=true`; paper-level or unverified licence evidence remains
fail-closed.

Use `python tools/import_external_action_surface.py --surface <surface>
--input-jsonl <local-export.jsonl>` to import a reviewed local export. The tool
validates the schema, refuses unreviewed or blocked surfaces, copies the JSONL to
the manifest directory, and writes `<artefact>.import.json` with the source hash,
licence review, row count, and target path.

Expected JSONL case schema: `id`, `action`, `label`, `category`, and `severity`
are required. Optional fields follow `benchmarks/data/action_corpus.jsonl`,
including `query`, `context`, `provenance`, `expected_route`, and `mcp_call`.

| Surface | Threat taxonomy | Licence | Provenance | Local artefact | Status |
|---|---|---|---|---|---|
| AgentDojo-style | Indirect prompt injection into tool/action use | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | agentdojo_action_cases.jsonl | absent |
| MSB MCP Security Bench-style | MCP server/tool security and confused-deputy misuse | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | msb_mcp_security_action_cases.jsonl | absent |
| MCPSecBench-style | MCP protocol attack and unsafe tool-call behaviour | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | mcpsecbench_action_cases.jsonl | absent |
| MCP-SafetyBench-style | MCP safety and tool-use attack surfaces | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | mcp_safetybench_action_cases.jsonl | absent |
| SkillInject-style | Skill/tool supply-chain instruction injection | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | skillinject_action_cases.jsonl | absent |
| InjecAgent-style | Agent tool-use injection and malicious instruction transfer | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | injecagent_action_cases.jsonl | absent |
| Agent Security Bench-style | Agent security tasks, unsafe action routing, and tool misuse | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | agent_security_bench_action_cases.jsonl | absent |
| Browser-computer-use injection-style | Browser/computer-use prompt injection, UI drift, and exfiltration | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | browser_computer_use_action_cases.jsonl | absent |
