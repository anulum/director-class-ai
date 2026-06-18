# Director-Class AI

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

## Python middleware

Applications that dispatch tools directly can put the SDK middleware in front of
their executor. Dry-run is the default; real execution requires both a permitting
Governor decision and `dry_run=False`.

```python
from director_class_ai.sdk import (
    ToolExecutionResult,
    ToolReviewMiddleware,
    ToolReviewRequest,
)


def executor(request: ToolReviewRequest) -> ToolExecutionResult:
    return ToolExecutionResult({"status": "ok"}, exit_code=0)


middleware = ToolReviewMiddleware.default(executor=executor)
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
discovery, tool calls, and tool responses, but it never dispatches tools.

```bash
director-class-mcp-gateway --host 127.0.0.1 --port 8765
```

## Command guard

For command-line workflows, `director-class-guard` reviews shell, database,
cloud, Kubernetes, HTTP, and custom commands before optional execution. It is
dry-run by default.

```bash
director-class-guard --surface kubernetes -- kubectl get pods
director-class-guard --surface shell --execute -- printf guard-ok
```

## Design

The ensemble runs detectors concurrently and cheap-first (tiered cascade), so the
common safe case clears in microseconds and only a flagged action pays for the
full ensemble. Every detector — content, integrity, or action — emits the same
`DetectorSignal`, and a per-plane fusion (fail-open content, fail-closed action)
resolves them into one `Verdict`. Architecture and roadmap: `docs/internal/`.

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

Public copy, investor copy, and demos use the same bounded claim language in
`docs/CLAIM_BOUNDARIES.md`. The primary category is runtime action-control and
evidence for autonomous agents. Do not claim comparative benchmark leadership,
certification, or production readiness until the corresponding evidence gates are
complete.

## Licence

Proprietary commercial — see `LICENSE`. Source visibility is **not** a grant of
rights; production use requires a commercial agreement (protoscience@anulum.li).

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

The approval transport package exposes the existing digest-scoped queue through
an operator-console adapter, signed webhook events, and a loopback JSON service.
Responses contain ticket digests, status, timestamps, expiry, and approver
digests only; raw actions and command output are not returned.

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
python -m pytest                       # tests + 100% coverage gate
ruff check director_class_ai tests benchmarks
ruff format --check director_class_ai tests benchmarks
mypy --strict director_class_ai
bandit -r director_class_ai -ll
uvx semgrep scan --config p/python --config p/security-audit director_class_ai   # SAST, no local install
python -m build --sdist --wheel        # packaging
```
