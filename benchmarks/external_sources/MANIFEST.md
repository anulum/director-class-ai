<!-- SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial -->
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

Expected JSONL case schema: `id`, `action`, `label`, `category`, and `severity`
are required. Optional fields follow `benchmarks/data/action_corpus.jsonl`,
including `query`, `context`, `provenance`, `expected_route`, and `mcp_call`.

| Surface | Threat taxonomy | Licence | Provenance | Local artefact | Status |
|---|---|---|---|---|---|
| AgentDojo-style | Indirect prompt injection into tool/action use | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | agentdojo_action_cases.jsonl | absent |
| SkillInject-style | Skill/tool supply-chain instruction injection | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | skillinject_action_cases.jsonl | absent |
| MCP-security | MCP confused-deputy, exfiltration, schema and tool-call misuse | Not vendored; verify upstream licence before local import | Local export required; not copied into this repo | mcp_security_action_cases.jsonl | absent |
