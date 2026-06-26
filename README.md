# Director-Class AI

<p align="center">
  <a href="https://github.com/anulum/director-class-ai/actions/workflows/ci.yml"><img src="https://github.com/anulum/director-class-ai/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/anulum/director-class-ai/actions/workflows/pre-commit.yml"><img src="https://github.com/anulum/director-class-ai/actions/workflows/pre-commit.yml/badge.svg" alt="Pre-commit"></a>
  <a href="https://github.com/anulum/director-class-ai/actions/workflows/codeql.yml"><img src="https://github.com/anulum/director-class-ai/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/anulum/director-class-ai"><img src="https://api.securityscorecards.dev/projects/github.com/anulum/director-class-ai/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://codecov.io/gh/anulum/director-class-ai"><img src="https://codecov.io/gh/anulum/director-class-ai/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BUSL--1.1-blue.svg" alt="License: BUSL-1.1"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"></a>
</p>

**Runtime action-control and evidence layer for autonomous AI agents.** A
separate commercial product from the Apache-licensed `director-ai` base:
Director-Class AI sits between an autonomous agent and its effectors. It reviews
high-impact shell, SQL, infrastructure, API, and MCP tool actions before
dispatch; uncertain or high-risk actions escalate to human approval and emit
tamper-evident audit/evidence records.

The parallel detector ensemble governs three planes at once —

- **Content** — is what the system *says* true and grounded?
- **Integrity** — was the input / context tampered with?
- **Action** — is what the system *does* safe to execute?

The action plane is the differentiator. Prompt and content checks are supporting
signals that feed effector-bound governance; they are not positioned as a
standalone prevention guarantee. Current benchmark evidence is local functional
evidence, not a public advantage claim.

## Action checkpoint in five lines

```python
from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.core import ParallelEnsembleScorer, EvaluationRequest

guard = ParallelEnsembleScorer([DestructiveCommandDetector()])
verdict = guard.evaluate(EvaluationRequest(action="rm -rf /"))
assert verdict.allow is False and verdict.requires_human is True
```

## Getting started

Use the onboarding guide for a clean local setup, first guard run, and evidence
boundary check:

```bash
python -m pip install -e ".[dev]"
python demos/action_checkpoint.py
make preflight
make bench-evidence
```

Content and integrity adapters that reuse Director-AI primitives are installed
explicitly with the bounded detector extra:

```bash
python -m pip install -e ".[detectors]"
python -m pytest tests/test_director_ai_contract.py -q --no-cov
```

Detailed operator docs live in `docs/`:

- `docs/index.md` — documentation index and runtime surface map.
- `docs/onboarding.md` — setup, first guard run, and local verification.
- `docs/demos.md` — command guard, SDK, MCP gateway, and SIEM export examples.
- `docs/evidence.md` — benchmark evidence and claim boundaries.
- `notebooks/action_checkpoint.ipynb` — notebook walkthrough of the action
  checkpoint.

## Python middleware

Applications that dispatch tools directly can put the SDK middleware in front of
their executor. Dry-run is the default; real execution requires both a permitting
Governor decision and `dry_run=False`. Production middleware should pass durable
approval and audit paths so escalations open digest-scoped tickets and every
decision lands in the hash-chained audit log.

```python
from director_class_ai.sdk import (
    ToolExecutionResult,
    ToolReviewMiddleware,
    ToolReviewRequest,
)


def executor(request: ToolReviewRequest) -> ToolExecutionResult:
    return ToolExecutionResult({"status": "ok"}, exit_code=0)


middleware = ToolReviewMiddleware.default(
    approval_store="runtime/approvals.json",
    audit_log="runtime/audit.jsonl",
    policy_profile="sdk",
    executor=executor,
)
decision = middleware.run(
    ToolReviewRequest(
        "fs.read",
        {"path": "README.md"},
        provenance="user",
        dry_run=False,
    )
)
assert decision.route == "allow"
```

## MCP gateway service

The package also exposes a local loopback MCP review service. It reviews
discovery, tool calls, and tool responses, but it never dispatches tools. The
service reads the approved head of the same Guardrail-as-Code ledger
(`--policy-store`, default `runtime/policy.json`) before MCP review, so an
approved posture supplies the live fusion thresholds and capability envelope for
gateway decisions. With no ledger or no approved head, the gateway keeps its
fail-closed defaults.

```bash
director-class-mcp-gateway --host 127.0.0.1 --port 8765
```

Binding outside loopback fails closed unless an operator key is supplied through
an environment variable. Protected requests include that value in the
`x-director-class-operator-key` header.

```bash
export DIRECTOR_CLASS_MCP_KEY='operator-key'
director-class-mcp-gateway --host 0.0.0.0 --operator-key-env DIRECTOR_CLASS_MCP_KEY
```

## Command guard

For command-line workflows, `director-class-guard` reviews shell, database,
cloud, Kubernetes, HTTP, and custom commands before optional execution. It is
dry-run by default, and on every run it appends a privacy-preserving entry to a
tamper-evident hash-chained audit log (`runtime/audit.jsonl`) and routes any
human-required escalation through a durable, digest-scoped approval queue
(`runtime/approvals.json`). Both paths are configurable with `--audit-log` and
`--approval-store`.

The posture in force is the approved head of a Guardrail-as-Code ledger
(`--policy-store`, default `runtime/policy.json`): a posture change approved
through `director-class-policy` governs the thresholds this review fuses with, so
an approved relaxation or tightening takes effect at the boundary. With no ledger
or no approved head, the guard keeps its fail-closed defaults.
For strict deployments, `--require-policy-store` blocks when that ledger has no
approved head, and `--live-profile <profile.toml>` blocks when the runtime's
live posture has drifted from the approved head before any command is reviewed.
Rollback is reviewed through the same ledger: `director-class-policy rollback`
opens a pending proposal, and a different reviewer must approve that proposal
before the prior posture becomes the approved head again.
`director-class-policy expose` replays both detector-signal thresholds and the
capability/origin envelope when corpus rows include `capability_context` and
`capability_grants`, so capability-only posture changes appear in the A/B delta.

```bash
director-class-guard --surface kubernetes -- kubectl get pods
director-class-guard --surface shell --execute -- printf guard-ok
```

An escalated action is not permitted on its own. The first review opens a pending
ticket bound to the action's request digest; a human approves it out of band with
`director-class-approve`, after which a single later `--execute` run is permitted
exactly once (the approval is single-use):

```bash
# 1. review escalates and prints a request_digest; the action is not permitted
director-class-guard --surface database -- "DROP TABLE audit_2019"
# 2. a different human approves that digest
director-class-approve pending
director-class-approve approve --digest <request_digest> --approver alice
# 3. one execution is now permitted; a second review is blocked again
director-class-guard --surface database --execute -- "DROP TABLE audit_2019"
```

A hard block (an injected, tainted, or exfiltration action) is never routed to
approval — it stays blocked regardless of who asked.
MCP trust-registry integrity findings are hard blocks too: unknown, lookalike,
unsigned, signature-mismatched, under-populated, schema-drifted, or
transport-mismatched tool registrations cannot be softened by user approval.

## External benchmark artefacts

External action benchmark rows are never inferred from benchmark names. A local
JSONL export must pass the source-review gate before it can enter the external
partition:

```bash
python tools/import_external_action_surface.py \
  --surface AgentDojo-style \
  --input-jsonl /path/to/licence-reviewed-export.jsonl
python -m benchmarks.action_evidence
```

The import tool refuses unreviewed surfaces, validates the action-case schema,
copies the artefact into `benchmarks/external_sources/`, and writes a receipt
containing the source hash and licence review. Current committed evidence still
reports external n=0 because no third-party JSONL artefacts are vendored.

## Design

The ensemble runs detectors concurrently and cheap-first (tiered cascade), so the
common safe case clears in microseconds and only a flagged action pays for the
full ensemble. Every detector — content, integrity, or action — emits the same
`DetectorSignal`, and a per-plane fusion (fail-open content, fail-closed action)
resolves them into one `Verdict`.

## Rust normalisation path

Wheels include the optional `director_class_ai._rust` PyO3 extension for
security-critical command de-obfuscation, destructive-command matching, and MCP
structural scanning, plus audit hash-chain and learned meta-classifier math
primitives. The Python APIs remain stable: they attempt the Rust implementation,
compare the result with the Python reference implementation, and fall back to
Python if parity fails or the extension is unavailable. Source-tree development
therefore stays pure Python, while packaged deployments can exercise the
compiled path.

## Claim boundaries

Public copy and demos use the same bounded claim language in
`docs/CLAIM_BOUNDARIES.md`. The primary category is runtime action-control and
evidence for autonomous agents. Do not claim comparative benchmark leadership,
certification, or production readiness until the corresponding evidence gates are
complete.

## Licence

Source-available under the **Business Source License 1.1** — see `LICENSE`. You
may read, modify, and self-host the Licensed Work for your own internal
operations, including in production. You may **not** offer it to third parties as
a hosted or managed service, or build a competing product on its governance,
action-control, kill-switch, or audit functionality, without a commercial licence
(protoscience@anulum.li). On the Change Date (2030-06-20) the licence converts to
Apache-2.0.

## SIEM/SOC export

`director-class-siem-export` verifies the tamper-evident audit chain before it
writes SIEM/SOC JSONL. Exported events contain decision ids, detector ids, policy
profile, approval state, request digest, verdict booleans, risk, and chain
metadata. Raw prompts, actions, context, responses, and command output are not in
the export schema.

```bash
director-class-siem-export runtime/audit.jsonl -o runtime/siem.jsonl
director-class-siem-export runtime/audit.jsonl
```

## Operator approvals

`director-class-approve` resolves the escalation tickets the command guard opens,
operating on the same durable queue:

```bash
director-class-approve pending
director-class-approve approve --digest <request_digest> --approver alice
director-class-approve deny --digest <request_digest> --approver alice
```

The approval transport package additionally exposes the digest-scoped queue
through an operator-console adapter, signed webhook events, and a loopback JSON
service. Responses contain ticket digests, status, timestamps, expiry, and
approver digests only; raw actions and command output are not returned.

```python
from director_class_ai.approvals import (
    ApprovalQueue,
    ApprovalService,
    ApprovalServiceConfig,
    OperatorApprovalConsole,
)

queue = ApprovalQueue("runtime/approvals.json")
console = OperatorApprovalConsole(queue)
service = ApprovalService(
    console,
    config=ApprovalServiceConfig(operator_key="operator-key"),
)
```

## Evidence packages

`director_class_ai.evidence` emits redacted decision evidence for audit,
compliance, and incident response. Packages bind the request digest, policy
profile, capability grant ids, detector firings, approval state, action route,
optional benchmark replay id, and hash-chain proof. Control mappings use bounded
language for OWASP LLM risks, NIST AI RMF / GenAI profile, MCP security
considerations, and buyer controls; they do not assert certification.

```python
from director_class_ai.evidence import build_evidence_package

package = build_evidence_package(decision, policy_profile="pilot")
event = package.to_json()
```

## Local verification

```bash
# Run focused tests for touched modules locally; CI owns the full suite.
ruff check director_class_ai tests benchmarks tools
ruff format --check director_class_ai tests benchmarks tools
mypy --strict director_class_ai
python tools/check_documentation_surface.py
python demos/action_checkpoint.py
bandit -r director_class_ai -ll
uvx semgrep scan --config p/python --config p/security-audit director_class_ai   # SAST, no local install
python -m build --sdist --wheel        # packaging
```
