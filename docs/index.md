# Director-Class AI Documentation

Director-Class AI is a runtime action-control and evidence layer for autonomous
agents. It sits at the effector boundary: before an agent runs a command, calls a
tool, touches MCP, exports evidence, or asks a human to approve a risky action.

Current evidence supports local functional behaviour. Do not use these docs to
claim comparative benchmark leadership, certification, or remote production
readiness until isolated benchmark runs, reviewed external artefacts, remote CI,
and repository protection are complete.

## Start Here

- [Onboarding](onboarding.md) — install, run the first guard, and verify the
  local gates.
- [Operator demo](demos.md) — run the command guard, SDK middleware, MCP gateway,
  and SIEM export examples.
- [Notebook](../notebooks/action_checkpoint.ipynb) — inspect the same action
  checkpoint workflow in notebook form.
- [Evidence and benchmarks](evidence.md) — understand what the committed numbers
  prove and what they do not prove.
- [Claim boundaries](CLAIM_BOUNDARIES.md) — use the canonical public language.

## Runtime Surfaces

| Surface | Entrypoint | Purpose |
|---|---|---|
| Python SDK | `director_class_ai.sdk.ToolReviewMiddleware` | Review arbitrary Python tool calls before an executor runs. |
| Command guard | `director-class-guard` | Review shell, database, cloud, Kubernetes, HTTP, and custom commands. |
| MCP gateway | `director-class-mcp-gateway` | Review MCP discovery, tool calls, and tool responses on loopback. |
| SIEM export | `director-class-siem-export` | Verify an audit chain and export redacted SOC events with bounded technique tags. |
| Evidence package | `director_class_ai.evidence` | Emit redacted decision packages with controls and bounded technique tags for audit and incident response. |

## Local Gates

```bash
make preflight
make bench-evidence
python demos/action_checkpoint.py
```

`make preflight` covers SPDX, test quality, boundary evidence, godfile limits,
repository readiness, Phase 4 intake, numeric-claim evidence, lint, formatting,
and strict typing. Run focused tests for touched modules locally; GitHub Actions
owns the full pytest coverage gate. Benchmark evidence remains local regression
evidence unless it is run with isolation and reviewed external artefacts.
