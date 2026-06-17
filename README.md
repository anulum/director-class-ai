# Director-Class AI

**High-assurance multi-detector governance for autonomous and mission-critical
systems.** A separate commercial product from the Apache-licensed `director-ai`
base: a parallel detector ensemble plus an action-plane effector kill-switch that
governs three planes at once —

- **Content** — is what the system *says* true and grounded?
- **Integrity** — was the input / context tampered with?
- **Action** — is what the system *does* safe to execute?

The action plane is the differentiator: a mandatory checkpoint between an
autonomous agent's decision and the real effector (shell, SQL, infra, API) that
catches catastrophic commands *before* they run. It is fail-closed — a missed
`rm -rf /` is catastrophic, a false block is a minor inconvenience — so an
uncertain critical action escalates to a human rather than being allowed.

## Kill-switch in five lines

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

## Design

The ensemble runs detectors concurrently and cheap-first (tiered cascade), so the
common safe case clears in microseconds and only a flagged action pays for the
full ensemble. Every detector — content, integrity, or action — emits the same
`DetectorSignal`, and a per-plane fusion (fail-open content, fail-closed action)
resolves them into one `Verdict`. Architecture and roadmap: `docs/internal/`.

## Licence

Proprietary commercial — see `LICENSE`. Source visibility is **not** a grant of
rights; production use requires a commercial agreement (protoscience@anulum.li).

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
